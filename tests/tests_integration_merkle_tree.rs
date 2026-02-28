use rusty_merkle_tree::MerkleTree;

#[test]
fn test_tree_can_handle_empty_strings_as_leaves() {
    let tree =
        MerkleTree::new(vec!["", "non-empty"]).expect("Failed to create tree with empty string");
    let root = tree.root();

    let proof = tree
        .formulate_proof_of_inclusion("")
        .expect("Failed to generate proof for empty string leaf");

    assert!(
        proof.verify(root, ""),
        "Verification failed for an empty string leaf"
    );
}

#[test]
fn test_dynamic_tree_multiple_additions_maintain_integrity() {
    let mut tree = MerkleTree::new(vec!["inicio"]).unwrap();

    tree.add_leaf("medio_1");
    tree.add_leaf("medio_2");
    tree.add_leaf("fin");

    assert_eq!(
        tree.leaves_count(),
        4,
        "Tree did not process multiple dynamic additions correctly"
    );

    let root = tree.root();

    for leaf in ["inicio", "medio_1", "medio_2", "fin"] {
        let proof = tree
            .formulate_proof_of_inclusion(leaf)
            .expect(&format!("Proof generation failed for leaf: {}", leaf));

        assert!(
            proof.verify(root, leaf),
            "Verification failed for leaf '{}' in a dynamically built tree",
            leaf
        );
    }
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
            "Proof generation failed unexpectedly for existing leaf: {}",
            leaf
        );

        let proof = proof_wrapper.unwrap();
        assert!(
            proof.verify(root, leaf),
            "Cryptographic verification failed for valid leaf: {}",
            leaf
        );
    }
}

#[test]
fn test_dynamic_tree_scales_across_multiple_levels() {
    let mut tree = MerkleTree::new(vec!["1", "2", "3", "4"]).unwrap();

    tree.add_leaf("5");
    let root = tree.root();

    let proof = tree
        .formulate_proof_of_inclusion("5")
        .expect("Failed to generate proof for leaf that forced a new tree level");

    assert!(
        proof.verify(root, "5"),
        "Failed to verify a leaf that triggered a level expansion in the dynamic tree"
    );
}

#[test]
fn test_tree_with_large_amount_of_identical_elements() {
    let data = vec!["duplicate"; 100];
    let tree = MerkleTree::new(data).expect("Failed to create tree with identical elements");
    let root = tree.root();

    let proof = tree
        .formulate_proof_of_inclusion("duplicate")
        .expect("Expected proof generation to succeed for identical elements");

    assert!(
        proof.verify(root, "duplicate"),
        "Verification failed in a tree populated entirely by identical leaves"
    );
}
