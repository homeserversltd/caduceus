use std::process::Command;

fn git(args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .output()
        .expect("Caduceus builds require git to embed the source SHA");
    assert!(
        output.status.success(),
        "git {} failed while embedding Caduceus source SHA",
        args.join(" ")
    );
    String::from_utf8(output.stdout)
        .expect("git output must be UTF-8")
        .trim()
        .to_string()
}

fn main() {
    let build_sha = git(&["rev-parse", "--verify", "HEAD"]);
    assert!(
        build_sha.len() == 40
            && build_sha
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
        "Caduceus source SHA must be 40 lowercase hexadecimal characters"
    );

    println!("cargo:rustc-env=CADUCEUS_BUILD_SHA={build_sha}");
    println!(
        "cargo:rerun-if-changed={}",
        git(&["rev-parse", "--git-path", "HEAD"])
    );
    println!(
        "cargo:rerun-if-changed={}",
        git(&["rev-parse", "--git-path", "packed-refs"])
    );
    if let Ok(output) = Command::new("git")
        .args(["symbolic-ref", "-q", "HEAD"])
        .output()
    {
        if output.status.success() {
            let reference = String::from_utf8(output.stdout)
                .expect("git reference must be UTF-8");
            let reference = reference.trim();
            if !reference.is_empty() {
                println!(
                    "cargo:rerun-if-changed={}",
                    git(&["rev-parse", "--git-path", reference])
                );
            }
        }
    }
}
