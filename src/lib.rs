use sha2::{Digest, Sha256};

pub struct MerkleTree {
    root: String,
    leaves: Vec<String>,
}

impl MerkleTree {
    pub fn new(array: Vec<&str>) -> Result<Self, String> {
        if array.is_empty() {
            return Err("You can't create an empty Merkle Tree".to_string());
        }

        let mut leaves = Vec::new();
        for element in array {
            let leave = Self::hash_element(element);
            leaves.push(leave);
        }

        let root = Self::calculate_merkle_root(&leaves);

        Ok(MerkleTree { root, leaves })
    }

    pub fn root(&self) -> &str {
        &self.root
    }

    pub fn leaves_count(&self) -> usize {
        self.leaves.len()
    }

    pub fn leaf_at(&self, idx: usize) -> &str {
        &self.leaves[idx]
    }

    fn calculate_merkle_root(leaves: &[String]) -> String {
        let root = match leaves {
            [] => unreachable!(""),
            [single] => single.clone(),
            [left, right] => {
                let combined = format!("{}{}", left, right);
                Self::hash_element(&combined)
            }
            _ => {
                let mut next_level_leaves = Vec::new();

                for pair in leaves.chunks(2) {
                    if pair.len() == 2 {
                        let combined = format!("{}{}", pair[0], pair[1]);
                        next_level_leaves.push(combined);
                    } else {
                        let combined = format!("{}{}", pair[0], pair[0]);
                        next_level_leaves.push(combined);
                    }
                }

                Self::calculate_merkle_root(&next_level_leaves)
            }
        };
        root
    }

    fn hash_element(element: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(element.as_bytes());
        let res = hasher.finalize();
        format!("{:x}", res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_tree_can_be_created_from_a_non_empty_array() {
        let data = vec!["hola", "mundo", "lambda", "class"];
        let tree = MerkleTree::new(data).unwrap();
        assert_eq!(tree.leaves_count(), 4);
    }

    #[test]
    fn merkle_tree_cant_be_created_from_an_empty_array() {
        let data: Vec<&str> = vec![];
        let tree_result = MerkleTree::new(data);

        assert!(tree_result.is_err());
    }

    #[test]
    fn merkle_tree_nodes_are_hashed() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]).unwrap();
        let idx = 0;
        let expected_hash_for_idx_0 =
            "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79"; //https://www.convertstring.com/es/Hash/SHA256
        assert_eq!(expected_hash_for_idx_0, tree.leaf_at(idx));
    }

    #[test]
    fn merkle_root_of_a_tree_of_one_leaf() {
        let tree = MerkleTree::new(vec!["hola"]).unwrap();
        let expected_hash_for_root =
            "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79";

        assert_eq!(tree.root(), expected_hash_for_root);
    }

    #[test]
    fn merkle_root_of_a_tree_with_two_leaves() {
        let tree = MerkleTree::new(vec!["hola", "mundo"]).unwrap();
        //hash(hash("hola") + hash("mundo"))
        let expected_root = "960429d8385f438788551f832e4eecf94a2006393b17c6c08a9fe678acb2047e";

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn merkle_root_of_a_tree_with_three_leaves() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda"]).unwrap();
        let expected_root = "e0aa7eae698c92a857be7279b942eac2c0468ea4381b18f5076c8a7073ea83c9";

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn merkle_root_of_a_tree_with_four_leaves() {
        let data = vec!["rust", "ethereum", "merkle", "tree"];
        let tree = MerkleTree::new(data).unwrap();

        let expected_root = "55896ca2b5ac3e3ec4ff00ae8f63dded63299ef916a537dd01adb1a440fb9d46";

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn merkle_root_of_a_tree_with_five_leaves() {
        let data = vec!["hola", "mundo", "lambda", "class", "rust"];
        let tree = MerkleTree::new(data).unwrap();

        let expected_root = "c21233588c19981bd7b6c11835197c6be7961dfce30a3e67b30fd545f665f342";

        assert_eq!(tree.root(), expected_root);
    }
}
