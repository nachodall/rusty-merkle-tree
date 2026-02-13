pub struct MerkleTree {
    nodes: Vec<String>,
}

impl MerkleTree {
    pub fn new(a: Vec<&str>) -> Self {
        let mut nodes = Vec::new();

        for s in a {
            nodes.push(s.to_string());
        }
        MerkleTree { nodes }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_can_be_created_from_an_array() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]);
        assert!(tree.nodes.len() == 4);
    }
}
