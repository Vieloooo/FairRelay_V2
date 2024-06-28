contract Judge{
    address PoMEVerifier; 
    mapping( bytes32 => uint256) public PoMETimes; 

    function submitPoME public ();
    // Check if a encryption commitment is logged. (if the corresbonding time H(H(plaintext), H(ciphertext), H(sk), index) is logged before time _T)
    function isCheating() public pure returns (bool) {
        return true;
    }
    
    function isLazy() public pure returns (bool) {
        return true;
    }
}