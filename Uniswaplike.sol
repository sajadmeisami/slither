pragma solidity ^0.4.24;

contract Example {

    bytes32 public DOMAIN_SEPARATOR;
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;
    mapping(address => uint) public nonces;

    constructor () public {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
                1,
                address(this)
            )
        );
    }


    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) internal returns (address){
        require(deadline >= block.timestamp, 'UniswapV2: EXPIRED');
        bytes32 digest = keccak256(
            abi.encodePacked(
                '\x19\x01',
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, deadline))
            )
        );
        address recoveredAddress = ecrecover(digest, v, r, s);
        return recoveredAddress;

    }

    function test(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) internal returns (address) {
        return permit(owner, spender, value, deadline, v, r, s);
    }
    function tolo(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external {
        address add = test(owner, spender, value, deadline, v, r, s);
        require(add != address(0) && add == owner, 'UniswapV2: INVALID_SIGNATURE');
    }
}
