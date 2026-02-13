use sha2::{Digest, Sha256};

pub struct MerkleTree {
    nodes: Vec<String>,
}

impl MerkleTree {
    pub fn new(array: Vec<&str>) -> Self {
        let mut nodes = Vec::new();

        for element in array {
            let node = Self::hash_element(element);
            nodes.push(node);
        }

        MerkleTree { nodes }
    }

    fn hash_element(element: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(element.as_bytes());
        let res = hasher.finalize();
        format!("{:x}", res)
    }

    pub fn leaves_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn leaf_at(&self, idx: usize) -> &str {
        &self.nodes[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_can_be_created_from_an_array() {
        let data = vec!["hola", "mundo", "lambda", "class"];
        let tree = MerkleTree::new(data);
        assert_eq!(tree.leaves_count(), 4);
    }

    #[test]
    fn merkle_tree_nodes_are_hashed() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]);
        let idx = 0;
        let expected_hash_for_idx_0 =
            "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79"; //https://www.convertstring.com/es/Hash/SHA256
        assert_eq!(expected_hash_for_idx_0, tree.leaf_at(idx));
    }
}
