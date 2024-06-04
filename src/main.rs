use std::env;
#[allow(unused_imports)]
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    // println!("Logs from your program will appear here!");
    let current_path = env::current_dir().unwrap();
    let path = env::var("PATH").unwrap_or_default();
    let path: Vec<PathBuf> = path.trim().split(":").map(|s| s.into()).collect();
    // println!("{:?}", path);

    let built_in = vec!["echo", "exit", "type", "pwd"];

    // Uncomment this block to pass the first stage
    loop {
        print!("$ ");
        io::stdout().flush().unwrap();

        // Wait for user input
        let stdin = io::stdin();
        let mut input = String::new();
        stdin.read_line(&mut input).unwrap();
        let vec: Vec<&str> = input.trim().split_whitespace().collect();
        match vec[0] {
            "exit" => {
                break;
            }
            "pwd" => {
                println!("{}", current_path.to_str().unwrap());
            }
            "echo" => {
                println!("{}", vec[1..].join(" "))
            }
            "type" => {
                if built_in.contains(&vec[1]) {
                    println!("{} is a shell builtin", vec[1]);
                } else {
                    match find(&path, vec[1].to_string().clone()) {
                        None => {
                            // should be:
                            // println!("{}: command not found", vec[1]);
                            println!("{}: not found", vec[1]);
                        }
                        Some(cmd) => {
                            println!("{} is {}", vec[1], cmd)
                        }
                    }
                }
            }
            _cmd => {
                match find(&path, _cmd.to_string()) {
                    None => {
                        println!("{}: command not found", vec[0]);
                    }
                    Some(cmd) => {
                        let mut command = Command::new(cmd);
                        vec[1..].iter().for_each(|arg| {
                            command.arg(arg);
                        });
                        let x = command.output();
                        print!("{}", String::from_utf8_lossy(x.unwrap().stdout.as_slice()));
                    }
                }
            }
        }
    }
}

fn find(paths: &Vec<PathBuf>, cmd: String) -> Option<String> {
    for path in paths {
        let mut path = path.clone();
        path.push(cmd.as_str());
        if path.is_file() {
            return Some(path.to_str().unwrap().to_string());
        }
    }
    None
}

#[test]
fn test_find() {
    let paths: Vec<PathBuf> = vec!["/bin"].iter().map(|s| s.into()).collect();
    println!("{:?}", find(&paths, "cat".to_string()));
}

#[test]
fn test_execute() {
    let mut command = Command::new("ls");
    command.arg("-l").arg("-a");
    let x = command.output();
    println!("{}", String::from_utf8_lossy(x.unwrap().stdout.as_slice()));

    println!("{}", env::current_dir().unwrap().to_str().unwrap());
}