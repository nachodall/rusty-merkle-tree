use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct MerkleTree {
    root: String,
    leaves: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Side {
    Left,
    Right,
}

#[derive(Debug, Clone)]
pub struct MerkleProof {
    pairs: Vec<(String, Side)>,
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

    pub fn formulate_proof_of_inclusion(&self, data: &str) -> Option<MerkleProof> {
        let leaf_hash = Self::hash_element(data);
        let index = self.leaves.iter().position(|h| h == &leaf_hash)?;

        let mut elements_of_proof = Vec::new();
        Self::formulate_proof_recursive(&self.leaves, index, &mut elements_of_proof);

        Some(MerkleProof {
            pairs: elements_of_proof,
        })
    }

    fn formulate_proof_recursive(
        current_level: &Vec<String>,
        index: usize,
        elements_of_proof: &mut Vec<(String, Side)>,
    ) {
        if current_level.len() <= 1 {
            return;
        }

        let is_even_index = index % 2 == 0;
        let pair_idx = if is_even_index {
            if index + 1 == current_level.len() {
                index
            } else {
                index + 1
            }
        } else {
            index - 1
        };

        let side = if is_even_index {
            Side::Right
        } else {
            Side::Left
        };

        elements_of_proof.push((current_level[pair_idx].clone(), side));

        Self::formulate_proof_recursive(
            &Self::calculate_next_level_of_tree(current_level),
            index / 2,
            elements_of_proof,
        );
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
                let next_level_of_tree = Self::calculate_next_level_of_tree(leaves);

                Self::calculate_merkle_root(&next_level_of_tree)
            }
        };
        root
    }

    fn calculate_next_level_of_tree(leaves: &[String]) -> Vec<String> {
        let mut next_level_of_tree = Vec::new();

        for pair in leaves.chunks(2) {
            if pair.len() == 2 {
                let combined = format!("{}{}", pair[0], pair[1]);
                next_level_of_tree.push(Self::hash_element(&combined));
            } else {
                let combined = format!("{}{}", pair[0], pair[0]);
                next_level_of_tree.push(Self::hash_element(&combined));
            }
        }

        next_level_of_tree
    }

    fn hash_element(element: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(element.as_bytes());
        let res = hasher.finalize();
        format!("{:x}", res)
    }
}

pub fn verify_proof_of_inclusion(
    root: &str,
    leaf: &str,
    proof_wrapper: &Option<MerkleProof>,
) -> bool {
    let proof = match proof_wrapper {
        Some(p) => p,
        None => return false,
    };

    let mut current_hash = MerkleTree::hash_element(leaf);

    for (sibling_hash, side) in &proof.pairs {
        let combined = match side {
            Side::Left => {
                format!("{}{}", sibling_hash, current_hash)
            }
            Side::Right => {
                format!("{}{}", current_hash, sibling_hash)
            }
        };
        current_hash = MerkleTree::hash_element(&combined);
    }

    current_hash == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_can_be_created_from_a_non_empty_array() {
        let data = vec!["hola", "mundo", "lambda", "class"];
        let tree = MerkleTree::new(data).unwrap();
        assert_eq!(tree.leaves_count(), 4);
    }

    #[test]
    fn test_merkle_tree_cant_be_created_from_an_empty_array() {
        let data: Vec<&str> = vec![];
        let tree_result = MerkleTree::new(data);

        assert!(tree_result.is_err());
    }

    #[test]
    fn test_merkle_tree_nodes_are_hashed() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda", "class"]).unwrap();
        let idx = 0;
        let expected_hash_for_idx_0 =
            "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79"; //https://www.convertstring.com/es/Hash/SHA256
        assert_eq!(expected_hash_for_idx_0, tree.leaf_at(idx));
    }

    #[test]
    fn test_merkle_root_of_a_tree_of_one_leaf() {
        let tree = MerkleTree::new(vec!["hola"]).unwrap();
        let expected_hash_for_root =
            "b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79";

        assert_eq!(tree.root(), expected_hash_for_root);
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_two_leaves() {
        let tree = MerkleTree::new(vec!["hola", "mundo"]).unwrap();
        //hash(hash("hola") + hash("mundo"))
        let expected_root = "960429d8385f438788551f832e4eecf94a2006393b17c6c08a9fe678acb2047e";

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_three_leaves() {
        let tree = MerkleTree::new(vec!["hola", "mundo", "lambda"]).unwrap();
        let expected_root = "b4b392e697e6ff773514142a4be8b8f25d6faa9ab4422faeadab9483abfedaf3";

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_four_leaves() {
        let data = vec!["rust", "ethereum", "merkle", "tree"];
        let tree = MerkleTree::new(data).unwrap();

        let expected_root = "87b80c3ccda5bfc52e736516eca761000e9ee6fd6172b92c2dae0707f7e4d367";

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_merkle_root_of_a_tree_with_five_leaves() {
        let data = vec!["hola", "mundo", "lambda", "class", "rust"];
        let tree = MerkleTree::new(data).unwrap();

        let expected_root = "7a9856ea15d79f0fc3e62da40195d3a525db3ee9f10ad9fb7b56ae325b45e14f";

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_verify_valid_proof() {
        let data = vec!["hola", "mundo", "lambda", "class"];
        let tree = MerkleTree::new(data.clone()).unwrap();
        let root = tree.root();

        let leaf_to_prove_inclusion = "lambda";

        let proof = tree.formulate_proof_of_inclusion(leaf_to_prove_inclusion);

        assert!(verify_proof_of_inclusion(
            root,
            leaf_to_prove_inclusion,
            &proof
        ));
    }

    #[test]
    fn test_proof_for_non_existent_leaf_fails() {
        let data = vec!["hola", "mundo", "lambda", "class"];
        let tree = MerkleTree::new(data).unwrap();
        let root = tree.root();

        let non_existent_leaf = "rust";

        let proof = tree.formulate_proof_of_inclusion(non_existent_leaf);
        assert!(proof.is_none());

        assert!(!verify_proof_of_inclusion(root, non_existent_leaf, &proof));
    }

    #[test]
    fn test_verify_altered_proof_fails() {
        let data = vec!["hola", "mundo", "lambda", "class"];
        let tree = MerkleTree::new(data).unwrap();
        let root = tree.root();

        let leaf_to_prove = "lambda";

        let mut proof = tree.formulate_proof_of_inclusion(leaf_to_prove).unwrap();
        proof.pairs[0].0 = "fake_hash_123".to_string();
        let proof_wrapper = Some(proof);
        assert!(!verify_proof_of_inclusion(
            root,
            leaf_to_prove,
            &proof_wrapper
        ));
    }

    #[test]
    fn test_verify_all_leaves_in_larger_tree_exhaustively() {
        let data = vec![
            "rust",
            "haskell",
            "c++",
            "python",
            "smalltalk",
            "java",
            "assembly",
            "javascript",
            "go",
            "lua",
            "lisp",
            "c",
            "c#",
            "fortran",
            "elixir",
            "zig",
            "ruby",
            "pascal",
            "prolog",
        ];

        let tree = MerkleTree::new(data.clone()).unwrap();
        let root = tree.root();

        for leaf in data {
            let proof_wrapper = tree.formulate_proof_of_inclusion(leaf);

            assert!(
                proof_wrapper.is_some(),
                "Proof was not generated for leaf: {}",
                leaf
            );

            assert!(
                verify_proof_of_inclusion(root, leaf, &proof_wrapper),
                "Verification failed for leaf: {}",
                leaf
            );
        }
    }
}
