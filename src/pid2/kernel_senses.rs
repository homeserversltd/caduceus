//! Native subscriptions for the namespace, link and file needs.
use super::{DirtyKey, Wake};
use std::{collections::{HashMap,HashSet,VecDeque}, ffi::{CString,OsString}, fs::{self,File,OpenOptions}, io::{self,Read}, os::{fd::{AsRawFd,FromRawFd,OwnedFd},unix::{ffi::OsStrExt,fs::{MetadataExt,OpenOptionsExt}}}, path::{Path,PathBuf}, sync::{Arc,RwLock,atomic::{AtomicBool,Ordering}}, time::Duration};
use tokio::{io::unix::AsyncFd, sync::watch, task::JoinHandle};

struct Task(JoinHandle<()>);
impl Drop for Task { fn drop(&mut self) { self.0.abort(); } }
impl Task {async fn stop(mut self) {self.0.abort();let _=(&mut self.0).await;}}

#[derive(Clone,Default,PartialEq,Eq)]
pub(in crate::pid2) struct Watched { pub names:HashSet<String>, pub links:HashSet<(String,String)>, pub files:HashSet<PathBuf> }
#[derive(Default)]
struct Rows { names:HashMap<String,Option<bool>>, links:HashMap<(String,String),Option<String>>, files:HashMap<PathBuf,Option<String>> }
#[derive(Default)]
pub(in crate::pid2) struct Cache { rows:RwLock<Rows>, watch_set_online:AtomicBool }
impl Cache {
    pub fn netns(&self,name:&str)->Option<bool> { if !self.watch_set_online.load(Ordering::Acquire) {return None;} self.rows.read().ok()?.names.get(name).copied().flatten() }
    pub fn link(&self,ns:&str,link:&str)->Option<String> { if !self.watch_set_online.load(Ordering::Acquire) {return None;} self.rows.read().ok()?.links.get(&(ns.into(),link.into())).cloned().flatten() }
    pub fn file(&self,path:&Path)->Option<String> { if !self.watch_set_online.load(Ordering::Acquire) {return None;} self.rows.read().ok()?.files.get(path).cloned().flatten() }
    pub fn offline_keys(&self)->Vec<DirtyKey> {
        let Ok(r)=self.rows.read() else {return Vec::new();};
        r.names.iter().filter_map(|(n,v)|v.is_none().then(||DirtyKey::Netns(n.clone())))
            .chain(r.links.iter().filter_map(|((n,l),v)|v.is_none().then(||DirtyKey::Link(n.clone(),l.clone()))))
            .chain(r.files.iter().filter_map(|(p,v)|v.is_none().then(||DirtyKey::File(p.clone())))).collect()
    }
    fn invalidate(&self) {
        self.watch_set_online.store(false,Ordering::Release);
        if let Ok(mut r)=self.rows.write() {
            for v in r.names.values_mut() {*v=None;}
            for v in r.links.values_mut() {*v=None;}
            for v in r.files.values_mut() {*v=None;}
        }
    }
    fn namespace(&self,tx:&Wake,name:&str,value:Option<bool>) {
        if let Ok(mut r)=self.rows.write() { if r.names.contains_key(name) && r.names.get(name)!=Some(&value) {r.names.insert(name.into(),value);drop(r);tx.push(DirtyKey::Netns(name.into()));} }
    }
    // Change the namespace and its link facts under one lock so no reader
    // can combine a new namespace epoch with facts from the old one.
    fn reset_namespace(&self,tx:&Wake,name:&str,wanted:&HashSet<String>,namespace:Option<bool>,link:Option<&str>) {
        let Ok(mut r)=self.rows.write() else {return;};
        let mut dirty=Vec::new();
        if let Some(v)=r.names.get_mut(name) {if *v!=namespace {*v=namespace;dirty.push(DirtyKey::Netns(name.into()));}}
        for name_link in wanted {
            if let Some(v)=r.links.get_mut(&(name.to_owned(),name_link.clone())) {
                let next=link.map(str::to_owned);
                if *v!=next {*v=next;dirty.push(DirtyKey::Link(name.into(),name_link.clone()));}
            }
        }
        drop(r);
        for key in dirty {tx.push(key);}
    }
    fn link_value(&self,tx:&Wake,ns:&str,link:&str,value:Option<String>) {
        let key=(ns.to_owned(),link.to_owned());
        if let Ok(mut r)=self.rows.write() { if r.links.contains_key(&key) && r.links.get(&key)!=Some(&value) {r.links.insert(key,value);drop(r);tx.push(DirtyKey::Link(ns.into(),link.into()));} }
    }
    fn file_value(&self,tx:&Wake,path:&Path,value:Option<String>) {
        if let Ok(mut r)=self.rows.write() { if r.files.contains_key(path) && r.files.get(path)!=Some(&value) {r.files.insert(path.into(),value);drop(r);tx.push(DirtyKey::File(path.into()));} }
    }
}

fn valid_name(name:&str)->bool { !name.is_empty() && name!="." && name!=".." && !name.contains('/') && !name.as_bytes().contains(&0) }
pub(in crate::pid2) fn valid_link(name:&str)->bool {valid_name(name) && name.len()<libc::IFNAMSIZ && !name.bytes().any(|b|b==b':' || b.is_ascii_whitespace())}
fn valid_path(path:&Path)->bool { path.is_absolute() && path.file_name().is_some() && !path.components().any(|c|matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir)) }

// One inotify fd watches the target's existing directory ancestors. Directory
// entries are filtered against the exact target and missing parents are followed.
struct DirWatch { fd:AsyncFd<OwnedFd>, dirs:HashMap<i32,PathBuf>, target:PathBuf }
impl DirWatch {
    fn open(target:&Path)->io::Result<Self> {
        let raw=unsafe {libc::inotify_init1(libc::IN_CLOEXEC|libc::IN_NONBLOCK)};
        if raw<0 {return Err(io::Error::last_os_error());}
        let owned=unsafe {OwnedFd::from_raw_fd(raw)};
        let mut dirs=HashMap::new();
        if let Some(parent)=target.parent() {
            for dir in parent.ancestors() {
                if !dir.is_dir() {continue;}
                let c=CString::new(dir.as_os_str().as_bytes()).map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,"NUL in watched path"))?;
                let mask=libc::IN_ONLYDIR|libc::IN_CREATE|libc::IN_DELETE|libc::IN_MOVED_FROM|libc::IN_MOVED_TO|libc::IN_CLOSE_WRITE|libc::IN_ATTRIB|libc::IN_DELETE_SELF|libc::IN_MOVE_SELF;
                let wd=unsafe {libc::inotify_add_watch(owned.as_raw_fd(),c.as_ptr(),mask)};
                if wd<0 {return Err(io::Error::last_os_error());}
                dirs.insert(wd,dir.to_path_buf());
            }
        }
        Ok(Self{fd:AsyncFd::new(owned)?,dirs,target:target.into()})
    }
    async fn changed(&self)->io::Result<bool> {
        let mut ready=self.fd.readable().await?;
        let mut relevant=false;
        let mut buffer=[0u8;16384];
        loop {
            let n=unsafe {libc::read(self.fd.get_ref().as_raw_fd(),buffer.as_mut_ptr().cast(),buffer.len())};
            if n<0 {let e=io::Error::last_os_error();if e.kind()==io::ErrorKind::Interrupted {continue;} if e.kind()==io::ErrorKind::WouldBlock {ready.clear_ready();return Ok(relevant);} return Err(e);}
            if n==0 {return Err(io::Error::new(io::ErrorKind::UnexpectedEof,"inotify closed"));}
            let mut offset=0usize;
            while offset<(n as usize) {
                if offset+std::mem::size_of::<libc::inotify_event>()>n as usize {return Err(io::Error::new(io::ErrorKind::InvalidData,"short inotify event"));}
                let event=unsafe {std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<libc::inotify_event>())};
                let end=offset+std::mem::size_of::<libc::inotify_event>()+event.len as usize;
                if end>n as usize {return Err(io::Error::new(io::ErrorKind::InvalidData,"invalid inotify event"));}
                if event.mask&libc::IN_Q_OVERFLOW!=0 {return Err(io::Error::new(io::ErrorKind::Other,"inotify overflow"));}
                if let Some(dir)=self.dirs.get(&event.wd) {
                    let start=offset+std::mem::size_of::<libc::inotify_event>();
                    let raw=&buffer[start..end];let len=raw.iter().position(|b|*b==0).unwrap_or(raw.len());
                    let changed=if len==0 {dir.clone()} else {dir.join(std::ffi::OsStr::from_bytes(&raw[..len]))};
                    if self.target==changed || self.target.starts_with(&changed) {relevant=true;}
                }
                offset=end;
            }
        }
    }
}

fn file_digest(path:&Path)->io::Result<String> {
    let mut file=match OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK|libc::O_CLOEXEC).open(path) {Ok(file)=>file,Err(e) if e.kind()==io::ErrorKind::NotFound || e.raw_os_error()==Some(libc::ENOTDIR)=>return Ok("absent".into()),Err(e)=>return Err(e)};
    if !file.metadata()?.is_file() {return Err(io::Error::new(io::ErrorKind::InvalidData,"not a regular file"));}
    let mut context=md5::Context::new();let mut bytes=[0u8;16384];
    loop {let n=file.read(&mut bytes)?;if n==0 {break;}context.consume(&bytes[..n]);}
    Ok(format!("md5:{:x}",context.compute()))
}
// Follow each symlink explicitly so the link entry and its referent both
// have event sources, including dangling links and links in parent paths.
fn file_watch_paths(path:&Path)->io::Result<Vec<PathBuf>> {
    fn parts(path:&Path)->VecDeque<OsString> {
        path.components().filter_map(|c|match c {
            std::path::Component::Normal(n)=>Some(n.to_os_string()),
            std::path::Component::ParentDir=>Some(OsString::from("..")),
            _=>None,
        }).collect()
    }
    let mut pending=parts(path);let mut resolved=PathBuf::from("/");
    let mut paths=vec![path.to_path_buf()];let mut followed=0;
    while let Some(part)=pending.pop_front() {
        if part==".." {resolved.pop();continue;}
        let candidate=resolved.join(part);
        match fs::symlink_metadata(&candidate) {
            Ok(meta) if meta.file_type().is_symlink()=>{
                followed+=1;
                if followed>40 {return Err(io::Error::new(io::ErrorKind::InvalidData,"too many file symlinks"));}
                paths.push(candidate.clone());let target=fs::read_link(candidate)?;
                if target.is_absolute() {resolved=PathBuf::from("/");}
                let mut next=parts(&target);next.append(&mut pending);pending=next;
            },
            Ok(_)=>resolved=candidate,
            Err(e) if e.kind()==io::ErrorKind::NotFound || e.raw_os_error()==Some(libc::ENOTDIR)=>{
                paths.push(candidate.clone());
                resolved=candidate;
                for part in pending {if part==".." {resolved.pop();}else{resolved.push(part);}}
                break;
            },
            Err(e)=>return Err(e),
        }
    }
    paths.push(resolved);paths.sort();paths.dedup();Ok(paths)
}
async fn file_once(tx:&Wake,cache:&Cache,path:&Path)->io::Result<()> {
    if !valid_path(path) {return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid file path"));}
    let mut races=0;
    loop {
        let paths=file_watch_paths(path)?;
        let watches:Vec<_>=paths.iter().map(|p|DirWatch::open(p)).collect::<io::Result<_>>()?;
        // If a link was replaced while the subscriptions were installed,
        // rebuild them before recording any value from the new target.
        if file_watch_paths(path)?!=paths {
            races+=1;
            if races==8 {return Err(io::Error::new(io::ErrorKind::Other,"file path changes during watch setup"));}
            continue;
        }
        races=0;
        cache.file_value(tx,path,Some(file_digest(path)?));
        let waits:Vec<_>=watches.iter().map(|watch|Box::pin(async move {
            loop {if watch.changed().await? {return Ok::<(),io::Error>(());}}
        })).collect();
        futures_util::future::select_all(waits).await.0?;
    }
}
async fn file_task(tx:Wake,cache:Arc<Cache>,path:PathBuf) {
    loop {
        if let Err(error)=file_once(&tx,&cache,&path).await {eprintln!("pid2-file-watch: {error}");}
        cache.file_value(&tx,&path,None);
        if tx.closed() {return;}
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

#[repr(C)]
struct NlHeader {len:u32,kind:u16,flags:u16,seq:u32,pid:u32}
#[repr(C)]
struct IfInfo {family:u8,pad:u8,kind:u16,index:i32,flags:u32,change:u32}
#[repr(C)]
struct Dump {head:NlHeader,info:IfInfo}
fn route_socket(file:File)->io::Result<OwnedFd> {
    // setns is thread-local: use a disposable native thread so no Tokio
    // worker can be left in the foreign namespace if restoration fails.
    std::thread::spawn(move || {
        if unsafe {libc::setns(file.as_raw_fd(),libc::CLONE_NEWNET)}<0 {return Err(io::Error::last_os_error());}
        let raw=unsafe {libc::socket(libc::AF_NETLINK,libc::SOCK_RAW|libc::SOCK_CLOEXEC|libc::SOCK_NONBLOCK,libc::NETLINK_ROUTE)};
        if raw<0 {return Err(io::Error::last_os_error());}
        let fd=unsafe {OwnedFd::from_raw_fd(raw)};
        let mut addr:libc::sockaddr_nl=unsafe {std::mem::zeroed()};addr.nl_family=libc::AF_NETLINK as _;addr.nl_groups=libc::RTMGRP_LINK as _;
        if unsafe {libc::bind(fd.as_raw_fd(),(&addr as *const libc::sockaddr_nl).cast(),std::mem::size_of::<libc::sockaddr_nl>() as _)}<0 {return Err(io::Error::last_os_error());}
        let request=Dump{head:NlHeader{len:std::mem::size_of::<Dump>() as _,kind:18,flags:1|0x300,seq:1,pid:0},info:IfInfo{family:libc::AF_UNSPEC as _,pad:0,kind:0,index:0,flags:0,change:0}};
        let mut kernel:libc::sockaddr_nl=unsafe {std::mem::zeroed()};kernel.nl_family=libc::AF_NETLINK as _;
        let n=unsafe {libc::sendto(fd.as_raw_fd(),(&request as *const Dump).cast(),std::mem::size_of::<Dump>(),0,(&kernel as *const libc::sockaddr_nl).cast(),std::mem::size_of::<libc::sockaddr_nl>() as _)};
        if n!=std::mem::size_of::<Dump>() as isize {return Err(io::Error::last_os_error());}
        Ok(fd)
    }).join().map_err(|_|io::Error::new(io::ErrorKind::Other,"namespace opener panicked"))?
}
fn ns_file_identity(file:&File)->io::Result<Option<(u64,u64)>> {
    let mut stat:libc::statfs=unsafe {std::mem::zeroed()};
    if unsafe {libc::fstatfs(file.as_raw_fd(),&mut stat)}<0 {return Err(io::Error::last_os_error());}
    // The empty iproute2 mountpoint appears before the namespace bind mount.
    if stat.f_type as u64!=0x6e736673 {return Ok(None);}
    let m=file.metadata()?;Ok(Some((m.dev(),m.ino())))
}
fn ns_identity(path:&Path)->io::Result<Option<(u64,u64)>> {
    let file=match File::open(path) {Ok(f)=>f,Err(e) if e.kind()==io::ErrorKind::NotFound=>return Ok(None),Err(e)=>return Err(e)};
    ns_file_identity(&file)
}
struct Netlink {
    fd:AsyncFd<OwnedFd>,identity:(u64,u64),indexes:HashMap<i32,(String,bool)>,
    pending:HashMap<i32,Option<(String,bool)>>,complete:bool,
    queries:HashMap<u32,(String,bool)>,deferred:HashSet<String>,next_seq:u32,
}
// A newly declared link gets a single named GETLINK request on the existing
// namespace socket, never another full dump or another socket.
fn query_link(net:&mut Netlink,name:&str)->io::Result<()> {
    if !valid_link(name) {return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid link name"));}
    let seq=net.next_seq;net.next_seq=net.next_seq.wrapping_add(1).max(2);
    let h=std::mem::size_of::<NlHeader>();let i=std::mem::size_of::<IfInfo>();
    let attr_len=4+name.len()+1;let len=h+i+(attr_len+3 & !3);
    let mut msg=vec![0u8;len];
    let header=NlHeader{len:len as u32,kind:18,flags:1,seq,pid:0};
    let info=IfInfo{family:libc::AF_UNSPEC as _,pad:0,kind:0,index:0,flags:0,change:0};
    unsafe {std::ptr::write_unaligned(msg.as_mut_ptr().cast::<NlHeader>(),header);std::ptr::write_unaligned(msg.as_mut_ptr().add(h).cast::<IfInfo>(),info);}
    msg[h+i..h+i+2].copy_from_slice(&(attr_len as u16).to_ne_bytes());
    msg[h+i+2..h+i+4].copy_from_slice(&3u16.to_ne_bytes());
    msg[h+i+4..h+i+4+name.len()].copy_from_slice(name.as_bytes());
    let mut kernel:libc::sockaddr_nl=unsafe {std::mem::zeroed()};kernel.nl_family=libc::AF_NETLINK as _;
    let sent=unsafe {libc::sendto(net.fd.get_ref().as_raw_fd(),msg.as_ptr().cast(),msg.len(),0,(&kernel as *const libc::sockaddr_nl).cast(),std::mem::size_of::<libc::sockaddr_nl>() as _)};
    if sent!=msg.len() as isize {return Err(io::Error::last_os_error());}
    net.queries.insert(seq,(name.to_owned(),false));Ok(())
}
fn parse_update(message:&[u8],indexes:&HashMap<i32,(String,bool)>)->io::Result<(i32,Option<(String,bool)>)> {
    let h=std::mem::size_of::<NlHeader>();let i=std::mem::size_of::<IfInfo>();
    if message.len()<h+i {return Err(io::Error::new(io::ErrorKind::InvalidData,"short link message"));}
    let info=unsafe {std::ptr::read_unaligned(message.as_ptr().add(h).cast::<IfInfo>())};

    let mut name=None;let mut p=h+i;
    while p+4<=message.len() {
        let len=u16::from_ne_bytes([message[p],message[p+1]]) as usize;let kind=u16::from_ne_bytes([message[p+2],message[p+3]])&0x3fff;
        if len<4 || p+len>message.len() {return Err(io::Error::new(io::ErrorKind::InvalidData,"invalid link attribute"));}
        if kind==3 {let b=&message[p+4..p+len];let end=b.iter().position(|v|*v==0).unwrap_or(b.len());name=std::str::from_utf8(&b[..end]).ok().map(str::to_owned);}
        p+=(len+3)&!3;
    }
    let name=name.or_else(||indexes.get(&info.index).map(|v|v.0.clone()));
    Ok((info.index,name.map(|name|(name,info.flags&1!=0))))
}
fn link_values(tx:&Wake,cache:&Cache,ns:&str,wanted:&HashSet<String>,indexes:&HashMap<i32,(String,bool)>) {
    for name in wanted {
        let state=indexes.values().find(|(n,_)|n==name).map_or("absent",|(_,up)|if *up {"up"}else{"down"});
        cache.link_value(tx,ns,name,Some(state.to_owned()));
    }
}
fn drain_netlink(net:&mut Netlink,tx:&Wake,cache:&Cache,ns:&str,path:&Path,wanted:&HashSet<String>)->io::Result<()> {
    let mut buf=[0u8;65536];
    loop {
        let n=unsafe {libc::recv(net.fd.get_ref().as_raw_fd(),buf.as_mut_ptr().cast(),buf.len(),libc::MSG_TRUNC)};
        if n<0 {let e=io::Error::last_os_error();if e.kind()==io::ErrorKind::Interrupted {continue;}if e.kind()==io::ErrorKind::WouldBlock {return Ok(());}return Err(e);}
        if n==0 || n as usize>buf.len() {return Err(io::Error::new(io::ErrorKind::InvalidData,"netlink lost or truncated"));}
        let mut off=0usize;
        while off<n as usize {
            if off+std::mem::size_of::<NlHeader>()>n as usize {return Err(io::Error::new(io::ErrorKind::InvalidData,"short netlink header"));}
            let header=unsafe {std::ptr::read_unaligned(buf.as_ptr().add(off).cast::<NlHeader>())};let len=header.len as usize;
            if len<std::mem::size_of::<NlHeader>() || off+len>n as usize {return Err(io::Error::new(io::ErrorKind::InvalidData,"invalid netlink length"));}
            let message=&buf[off..off+len];
            match header.kind {
                16|17=>{
                    let (index,mut row)=parse_update(message,&net.indexes)?;
                    if header.kind==16 && row.is_none() {
                        if let Some(Some((name,_)))=net.pending.get(&index) {
                            let info=unsafe {std::ptr::read_unaligned(message.as_ptr().add(std::mem::size_of::<NlHeader>()).cast::<IfInfo>())};
                            row=Some((name.clone(),info.flags&1!=0));
                        }
                    }
                    if header.seq==0 {
                        let event_name=row.as_ref().map(|v|v.0.as_str()).or_else(||net.indexes.get(&index).map(|v|v.0.as_str()));
                        if let Some(name)=event_name {for (wanted,superseded) in net.queries.values_mut() {if wanted==name {*superseded=true;}}}
                    }
                    let skip=if header.seq>1 {net.queries.remove(&header.seq).is_some_and(|(_,superseded)|superseded)} else {false};
                    if skip {off+=(len+3)&!3;continue;}
                    let known=net.indexes.contains_key(&index) || net.pending.contains_key(&index);
                    let named_delete=header.kind==17 && row.as_ref().is_some_and(|(name,_)|wanted.contains(name));
                    let selected=if header.kind==17 {None} else {row.filter(|(name,_)|wanted.contains(name))};
                    if selected.is_some() || known || named_delete {
                        if !net.complete && header.seq==0 {net.pending.insert(index,selected);} else {match selected {Some(v)=>{net.indexes.insert(index,v);},None=>{net.indexes.remove(&index);}}}
                    }
                },
                3 if header.seq==1 && !net.complete=>{
                    if header.flags&0x10!=0 {return Err(io::Error::new(io::ErrorKind::Other,"interrupted link dump"));}
                    let h=std::mem::size_of::<NlHeader>();
                    if message.len()>=h+4 && i32::from_ne_bytes(message[h..h+4].try_into().unwrap())!=0 {return Err(io::Error::new(io::ErrorKind::Other,"link dump error"));}
                    for (index,row) in std::mem::take(&mut net.pending) {match row {Some(v)=>{net.indexes.insert(index,v);},None=>{net.indexes.remove(&index);}}}
                    net.complete=true;
                },
                2=>{
                    let h=std::mem::size_of::<NlHeader>();
                    let code=if message.len()>=h+4 {i32::from_ne_bytes(message[h..h+4].try_into().unwrap())} else {return Err(io::Error::new(io::ErrorKind::InvalidData,"short netlink error"));};
                    if let Some((name,superseded))=net.queries.remove(&header.seq) {
                        if code!=-libc::ENODEV && code!=-libc::ENOENT {return Err(io::Error::from_raw_os_error(-code));}
                        if !superseded {net.indexes.retain(|_,(n,_)|n!=&name);}
                    } else {return Err(io::Error::new(io::ErrorKind::Other,"netlink error"));}
                },
                _=>{},
            }
            off+=(len+3)&!3;
        }
        if net.complete {
            for name in std::mem::take(&mut net.deferred) {if wanted.contains(&name) {query_link(net,&name)?;}}
            let unresolved:HashSet<_>=net.queries.values().filter_map(|(n,superseded)|(!superseded).then_some(n.clone())).collect();
            let ready:HashSet<_>=wanted.difference(&unresolved).cloned().collect();
            if ns_identity(path)?!=Some(net.identity) {return Err(io::Error::new(io::ErrorKind::Interrupted,"namespace identity changed"));}
            link_values(tx,cache,ns,&ready,&net.indexes);
        }
    }
}
async fn net_ready(net:&Option<Netlink>)->io::Result<()> {
    match net {Some(net)=>{let mut ready=net.fd.readable().await?;ready.clear_ready();Ok(())},None=>std::future::pending().await}
}
async fn namespace_once(tx:&Wake,cache:&Cache,name:&str,links:&mut watch::Receiver<HashSet<String>>,mounts:&mut watch::Receiver<()>)->io::Result<()> {
    let mut wanted=links.borrow_and_update().clone();
    if !valid_name(name) || wanted.iter().any(|n|!valid_link(n)) {return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid namespace or link"));}
    let path=Path::new("/run/netns").join(name);let mut net:Option<Netlink>=None;
    loop {
        let watcher=DirWatch::open(&path)?;
        let identity=ns_identity(&path)?;
        if identity.is_none() {cache.reset_namespace(tx,name,&wanted,Some(false),Some("absent"));net=None;}
        else if net.as_ref().is_none_or(|n|Some(n.identity)!=identity) {
            // Publish a present namespace only after its link dump is ready;
            // otherwise a combined need could read the previous namespace's facts.
            cache.reset_namespace(tx,name,&wanted,None,None);
            // Bind from the descriptor whose identity was checked, not a
            // second pathname open that could race a namespace replacement.
            let file=File::open(&path)?;
            if ns_file_identity(&file)?!=identity {continue;}
            let fd=route_socket(file)?;
            if ns_identity(&path)?!=identity {continue;}
            net=Some(Netlink{fd:AsyncFd::new(fd)?,identity:identity.unwrap(),indexes:HashMap::new(),pending:HashMap::new(),complete:false,queries:HashMap::new(),deferred:HashSet::new(),next_seq:2});
        }
        loop {
            tokio::select! {
                event=watcher.changed()=>{if event? {break;}},
                result=mounts.changed()=>{if result.is_err() {return Ok(());} if ns_identity(&path)?!=identity {break;}},
                result=links.changed()=>{
                    if result.is_err() {return Ok(());}
                    if ns_identity(&path)?!=identity {break;}
                    let next=links.borrow_and_update().clone();
                    if next.iter().any(|n|!valid_link(n)) {return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid link"));}
                    if let Some(net)=net.as_mut() {
                        net.indexes.retain(|_,(n,_)|next.contains(n));
                        net.deferred.retain(|n|next.contains(n));
                        net.pending.retain(|_,row|row.as_ref().is_none_or(|(n,_)|next.contains(n)));
                        for (n,superseded) in net.queries.values_mut() {if !next.contains(n) {*superseded=true;}}
                        for added in next.difference(&wanted) {
                            if net.complete {query_link(net,added)?;} else {net.deferred.insert(added.clone());}
                        }
                        let unresolved:HashSet<_>=net.queries.values().filter_map(|(n,s)|(!s).then_some(n.clone())).collect();
                        let ready:HashSet<_>=next.difference(&unresolved).filter(|n|!net.deferred.contains(*n)).cloned().collect();
                        if net.complete {link_values(tx,cache,name,&ready,&net.indexes);}
                    } else {for added in next.difference(&wanted) {cache.link_value(tx,name,added,Some("absent".into()));}}
                    wanted=next;
                },
                result=net_ready(&net)=>{
                    result?;
                    if ns_identity(&path)?!=identity {break;}
                    if let Some(net)=net.as_mut() {
                        match drain_netlink(net,tx,cache,name,&path,&wanted) {
                            Err(e) if e.kind()==io::ErrorKind::Interrupted=>break,
                            other=>other?,
                        }
                        if ns_identity(&path)?!=identity {break;}
                        if net.complete {cache.namespace(tx,name,Some(true));}
                    }
                },
            }
        }
    }
}
async fn namespace_task(tx:Wake,cache:Arc<Cache>,name:String,mut links:watch::Receiver<HashSet<String>>,mut mounts:watch::Receiver<()>) {
    loop {
        if let Err(error)=namespace_once(&tx,&cache,&name,&mut links,&mut mounts).await {eprintln!("pid2-netns-watch: {error}");}
        cache.reset_namespace(&tx,&name,&links.borrow(),None,None);
        if tx.closed(){return;}
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

pub(super) async fn run(tx:Wake,cache:Arc<Cache>,mut changed:watch::Receiver<()>,mounts:watch::Receiver<()>) {
    let mut namespaces:HashMap<String,(watch::Sender<HashSet<String>>,Task)>=HashMap::new();
    let mut files:HashMap<PathBuf,Task>=HashMap::new();
    loop {
        match crate::pid2::solver::watched_kernel() {
            Ok(next)=>{
                if let Ok(mut rows)=cache.rows.write() {
                    rows.names.retain(|k,_|next.names.contains(k));rows.links.retain(|k,_|next.links.contains(k));rows.files.retain(|k,_|next.files.contains(k));
                    for name in &next.names {rows.names.entry(name.clone()).or_insert(None);}
                    for link in &next.links {rows.links.entry(link.clone()).or_insert(None);}
                    for path in &next.files {rows.files.entry(path.clone()).or_insert(None);}
                }
                cache.watch_set_online.store(true,Ordering::Release);
                let stale:Vec<_>=namespaces.keys().filter(|n|!next.names.contains(*n)).cloned().collect();
                for n in stale {namespaces.remove(&n);}
                for name in &next.names {
                    let links:HashSet<String>=next.links.iter().filter(|(ns,link)|ns==name && valid_link(link)).map(|(_,link)|link.clone()).collect();
                    if let Some((sender,_))=namespaces.get(name) {
                        let changed=*sender.borrow()!=links;
                        if changed {sender.send_replace(links);}
                    } else {
                        let (sender,receiver)=watch::channel(links);
                        let task=tokio::spawn(namespace_task(tx.clone(),cache.clone(),name.clone(),receiver,mounts.clone()));
                        namespaces.insert(name.clone(),(sender,Task(task)));
                    }
                }
                let stale:Vec<_>=files.keys().filter(|p|!next.files.contains(*p)).cloned().collect();
                for p in stale {files.remove(&p);}
                for path in &next.files {if !files.contains_key(path) {files.insert(path.clone(),Task(tokio::spawn(file_task(tx.clone(),cache.clone(),path.clone()))));}}
            },
            Err(error)=>{
                eprintln!("pid2-kernel-watch-set: {error}");
                cache.invalidate();
                for scope in ["netns","link","file"] {tx.offline(scope);}
                for (_,(_,task)) in namespaces.drain() {task.stop().await;}
                for (_,task) in files.drain() {task.stop().await;}
                cache.invalidate();
                tokio::select! {
                    result=changed.changed()=>if result.is_err(){break;},
                    _=tokio::time::sleep(Duration::from_secs(300))=>{},
                }
                continue;
            },
        }
        if changed.changed().await.is_err(){break;}
    }
    // Dropping the task guards also cancels their kernel subscriptions.
}
