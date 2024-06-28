pragma solidity ^0.8.0;

contract PaymentChannel {
    // public vars
    enum ChannelStatus {
        NOTREADY,
        WORKING,
        CLOSING,
        CLOSED
    }
    address public judge; 
    address payable public sender;
    address payable public recipient;
    uint256 public senderBalance; // Sender balance of the channel
    uint256 public recipientBalance; // Recipient balance of the channel
    uint256 sequenceNum; // State sequence number of the channel
    uint256 public expiration; // Channel state, is not closing if expiration is 0
    ChannelStatus public status;

    // structures
    struct ChannelState {
        address addr;
        uint256 lb;
        uint256 rb;
        uint256 sn;
    }
    // Events
    event Opened(
        address channelADDR,
        address leftUser,
        address rightUser,
        uint256 leftBalance,
        uint256 rightBalance
    );
    event Updated(
        address channelADDR,
        uint256 leftBalance,
        uint256 rightBalance,
        uint256 sequenceNum
    );
    event Closing(address channelADDR, uint256 expiration);
    event Closed(
        address channelADDR,
        uint256 leftBalance,
        uint256 rightBalance
    );

    constructor(address payable _recipient, address _judge) payable {
        sender = payable(msg.sender);
        recipient = _recipient;
        senderBalance = msg.value;
        status = ChannelStatus.NOTREADY;
        judge = _judge;
        emit Opened(
            address(this),
            sender,
            recipient,
            senderBalance,
            recipientBalance
        );
    }

    // Receipient Top funds
    receive() external payable {
        require(
            msg.sender == recipient,
            "Can not funded once by the recipient"
        );
        require(
            status == ChannelStatus.NOTREADY,
            "Can not funded after NOTREADY stage"
        );
        recipientBalance = msg.value;
        status = ChannelStatus.WORKING;
        sequenceNum = 0;
        emit Opened(
            address(this),
            sender,
            recipient,
            senderBalance,
            recipientBalance
        );
    }

    // Update channel state with 2-2 signature directly
    function updateDirect(
        bytes memory _senderSignature,
        bytes memory _recipientSignature,
        ChannelState calldata _newState
    ) public {
        // Check channel state
        require(status != ChannelStatus.CLOSED, "Channel closed");
        // Check if the new state has a bigger sequence number
        require(_newState.sn > sequenceNum, "Invalid sequence number");
        // Check if the new state targets this channel
        require(_newState.addr == address(this), "Invalid channel address");
        // Check state
        require(
            _newState.lb + _newState.rb == senderBalance + recipientBalance,
            "Invalid state"
        );
        // Check if both signatures are valid, lu and ru sign the new state
        require(
            _recoverSigner(
                keccak256(
                    abi.encodePacked(
                        _newState.addr,
                        _newState.lb,
                        _newState.rb,
                        _newState.sn
                    )
                ),
                _senderSignature
            ) == sender,
            "Invalid sender signature"
        );

        require(
            _recoverSigner(
                keccak256(
                    abi.encodePacked(
                        _newState.addr,
                        _newState.lb,
                        _newState.rb,
                        _newState.sn
                    )
                ),
                _recipientSignature
            ) == recipient,
            "Invalid recipient signature"
        );

        // update the channel state
        senderBalance = _newState.lb;
        recipientBalance = _newState.rb;
        sequenceNum = _newState.sn;
        status = ChannelStatus.WORKING;
        emit Updated(
            address(this),
            senderBalance,
            recipientBalance,
            sequenceNum
        );
    }
    // Update channel state with 2-2 signature and a POME logged on time 

    // Update channel state with 2-2 signature and Judge contract say it is lazy. 
    
    // Try to close the channel
    function tryToClose() public {
        require(
            status == ChannelStatus.WORKING || status == ChannelStatus.NOTREADY,
            "Channel cannot be closed"
        );
        if (status == ChannelStatus.NOTREADY) {
            // transfer the balance to the sender
            sender.transfer(address(this).balance);
            status = ChannelStatus.CLOSED;
            emit Closed(address(this), senderBalance, recipientBalance);
        } else if (status == ChannelStatus.WORKING) {
            expiration = block.timestamp + 10;
            status = ChannelStatus.CLOSING;
            emit Closing(address(this), expiration);
        }
    }

    // Withdrawal function, used to transfer the contract balance to an external private account
    function close() public {
        require(
            status == ChannelStatus.CLOSING && block.timestamp > expiration,
            "Channel hasn't been closed"
        );
        if (recipientBalance > 0) {
            recipient.transfer(recipientBalance);
        }
        if (senderBalance > 0) {
            sender.transfer(address(this).balance);
        }
        status = ChannelStatus.CLOSED;
        emit Closed(address(this), senderBalance, recipientBalance);
    }

    // Recover signer address from _msgHash and _signature
    // _msgHash：message hash valueto
    // _signature：signature, using value pass since using the mload memory operation
    function _recoverSigner(
        bytes32 _msgHash,
        bytes memory _signature
    ) internal pure returns (address) {
        // Add Ethereum Signed Message prefix
        bytes32 prefixedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", _msgHash)
        );

        // Check signature length, 65 is the standard length for r,s,v signature
        require(_signature.length == 65, "invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Currently only assembly can be used to obtain the values of r, s, v from the signature
        assembly {
            /*
            The first 32 bytes store the length of the signature (dynamic array storage rule)
            add(sig, 32) = sig's pointer + 32
            Equivalent to skipping the first 32 bytes of the signature
            mload(p) loads the next 32 bytes of data starting from memory address p
            */
            // Read the next 32 bytes after the length data
            r := mload(add(_signature, 0x20))
            // Read the next 32 bytes
            s := mload(add(_signature, 0x40))
            // Read the last byte
            v := byte(0, mload(add(_signature, 0x60)))
        }
        // Use ecrecover (global function): recover the signer address using prefixedHash and r, s, v
        return ecrecover(prefixedHash, v, r, s);
    }
}
