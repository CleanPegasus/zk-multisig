// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./verifier.sol";

contract MultiSigWallet is Groth16Verifier {
    event Deposit(address indexed sender, uint256 amount, uint256 balance);
    event SubmitTransaction(
        address indexed owner,
        uint256 indexed txIndex,
        address indexed to,
        uint256 value,
        bytes data
    );
    event ConfirmTransaction(address indexed owner, uint256 indexed txIndex);
    event RevokeConfirmation(address indexed owner, uint256 indexed txIndex);
    event ExecuteTransaction(address indexed owner, uint256 indexed txIndex);

    uint256[] public ownersHash;
    mapping(uint256 => bool) public isOwnerHash;
    mapping(uint256 => bool) public isAttested;
    uint256 public numConfirmationsRequired;

    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
        uint256 numConfirmations;
    }

    // mapping from tx index => owner => bool
    mapping(uint256 => mapping(address => bool)) public isConfirmed;

    Transaction[] public transactions;

    modifier txExists(uint256 _txIndex) {
        require(_txIndex < transactions.length, "tx does not exist");
        _;
    }

    modifier notExecuted(uint256 _txIndex) {
        require(!transactions[_txIndex].executed, "tx already executed");
        _;
    }

    modifier notConfirmed(uint256 _txIndex) {
        require(!isConfirmed[_txIndex][msg.sender], "tx already confirmed");
        _;
    }

    constructor(uint256[] memory _ownersHash, uint256 _numConfirmationsRequired) {
        require(_ownersHash.length > 0, "owners required");
        require(
            _numConfirmationsRequired > 0
                && _numConfirmationsRequired <= _ownersHash.length,
            "invalid number of required confirmations"
        );

        for (uint256 i = 0; i < _ownersHash.length; i++) {
            uint256 ownerHash = _ownersHash[i];

            require(!isOwnerHash[ownerHash], "owner not unique");

            isOwnerHash[ownerHash] = true;
            ownersHash.push(ownerHash);
        }

        numConfirmationsRequired = _numConfirmationsRequired;
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value, address(this).balance);
    }

    function submitTransaction(address _to, uint256 _value, bytes memory _data, uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[5] calldata _pubSignals)
        public
    {
        uint256 txIndex = transactions.length;

        uint256 msgHash = uint256(keccak256(abi.encode(_to, _value, _data)));
        verifyOwnership(msgHash, _pA, _pB, _pC, _pubSignals);

        transactions.push(
            Transaction({
                to: _to,
                value: _value,
                data: _data,
                executed: false,
                numConfirmations: 0
            })
        );

        emit SubmitTransaction(msg.sender, txIndex, _to, _value, _data);
    }

    function confirmTransaction(uint256 _txIndex, uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[5] calldata _pubSignals)
        public
        txExists(_txIndex)
        notExecuted(_txIndex)
        notConfirmed(_txIndex)
    {
        uint256 txIndex = transactions.length;
        Transaction storage transaction = transactions[_txIndex];
        uint256 msgHash = uint256(keccak256(abi.encode(transaction.to, transaction.value, transaction.data)));
        verifyOwnership(msgHash, _pA, _pB, _pC, _pubSignals);
        transaction.numConfirmations += 1;
        isConfirmed[_txIndex][msg.sender] = true;

        emit ConfirmTransaction(msg.sender, _txIndex);
    }

    function executeTransaction(uint256 _txIndex)
        public
        txExists(_txIndex)
        notExecuted(_txIndex)
    {
        Transaction storage transaction = transactions[_txIndex];

        require(
            transaction.numConfirmations >= numConfirmationsRequired,
            "cannot execute tx"
        );

        transaction.executed = true;

        (bool success,) =
            transaction.to.call{value: transaction.value}(transaction.data);
        require(success, "tx failed");

        emit ExecuteTransaction(msg.sender, _txIndex);
    }

    function revokeConfirmation(uint256 _txIndex, uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[5] calldata _pubSignals)
        public
        txExists(_txIndex)
        notExecuted(_txIndex)
    {
        Transaction storage transaction = transactions[_txIndex];

        uint256 txIndex = transactions.length;

        uint256 msgHash = uint256(keccak256(abi.encode(transaction.to, transaction.value, transaction.data)));
        verifyOwnership(msgHash, _pA, _pB, _pC, _pubSignals);

        require(isConfirmed[_txIndex][msg.sender], "tx not confirmed");

        transaction.numConfirmations -= 1;
        isConfirmed[_txIndex][msg.sender] = false;

        emit RevokeConfirmation(msg.sender, _txIndex);
    }

    // pubSig[0] - msgAttestation
    // pubSig[1] - msgHash,
    // 
    function verifyOwnership(uint256 msgHash, uint256[2] calldata _pA, uint256[2][2] calldata _pB, uint256[2] calldata _pC, uint256[5] calldata _pubSignals) internal {
      require(isAttested[_pubSignals[0]] == false, "Attestation already used");
      require(msgHash == _pubSignals[1], "Invalid message signed");
      require(isOwnerHash[_pubSignals[2]] || isOwnerHash[_pubSignals[3]] || isOwnerHash[_pubSignals[4]], "Invalid Address Signed the message");
      require(verifyProof(_pA, _pB, _pC, _pubSignals), "Invalid Proof");
      isAttested[_pubSignals[0]] = true;
    }

    function getOwnersHash() public view returns (uint256[] memory) {
        return ownersHash;
    }

    function getTransactionCount() public view returns (uint256) {
        return transactions.length;
    }

    function getTransaction(uint256 _txIndex)
        public
        view
        returns (
            address to,
            uint256 value,
            bytes memory data,
            bool executed,
            uint256 numConfirmations
        )
    {
        Transaction storage transaction = transactions[_txIndex];

        return (
            transaction.to,
            transaction.value,
            transaction.data,
            transaction.executed,
            transaction.numConfirmations
        );
    }
}
