#[allow(unused)]
#[derive(Debug)]
pub struct TrieTree {
    root: Node,
}

#[allow(unused)]
#[derive(Debug)]
pub struct Node {
    path: char,
    pass: usize,
    end: usize,
}

#[allow(unused)]
impl Node {
    pub fn new(path: char) -> Node {
        Node {
            path,
            pass: 0,
            end: 0,
        }
    }
}
