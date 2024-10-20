const hre = require("hardhat");
const circomlibjs = require("circomlibjs");
const { keccak256 } = require("ethereumjs-util");
const { AbiCoder } = require("ethers");
const crypto = require("crypto");
const ethUtil = require("ethereumjs-util");
const snarkjs = require("snarkjs");
const fs = require("fs");

async function poseidonHash(inputs) {
  const poseidon = await circomlibjs.buildPoseidon();
  const poseidonHash = poseidon.F.toString(poseidon(inputs));
  return poseidonHash;
}

function generateMockPrivateKey() {
  return crypto.randomBytes(32).toString("hex");
}

function generateEthereumAddress(privateKey) {
  privateKey = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
  const privateKeyBuffer = Buffer.from(privateKey, "hex");
  const publicKey = ethUtil.privateToPublic(privateKeyBuffer);
  const address = ethUtil.publicToAddress(publicKey).toString("hex");
  return `0x${address}`;
}

function decomposeKey(key, n, k) {
  const totalBits = n * k;
  const keyBigInt = BigInt(`0x${key}`);

  // Ensure the key fits in the specified number of bits
  const maxValue = BigInt(2) ** BigInt(totalBits) - BigInt(1);
  const adjustedKey = keyBigInt & maxValue;

  const registers = [];
  const mask = BigInt(2) ** BigInt(n) - BigInt(1);

  for (let i = 0; i < k; i++) {
    const register = (adjustedKey >> BigInt(i * n)) & mask;
    registers.push(register.toString());
  }

  return registers;
}

async function main() {
  const [deployer] = await hre.ethers.getSigners();

  console.log("Deploying contracts with the account:", deployer.address);

  const Groth16Verifier = await hre.ethers.getContractFactory("Groth16Verifier");
  const verifier = await Groth16Verifier.deploy();

  const MultiSigWallet = await hre.ethers.getContractFactory("MultiSigWallet");

  const ownersPk = [
    generateMockPrivateKey(),
    generateMockPrivateKey(),
    generateMockPrivateKey(),
  ];

  const ownersDecomposedPk = [
    decomposeKey(ownersPk[0], 64, 4),
    decomposeKey(ownersPk[1], 64, 4),
    decomposeKey(ownersPk[2], 64, 4),
  ];

  const owners = [
    generateEthereumAddress(ownersPk[0]),
    generateEthereumAddress(ownersPk[1]),
    generateEthereumAddress(ownersPk[2]),
  ];

  const ownersPoshash = await Promise.all(owners.map( async (owner) => {
    let ownerBigInt = BigInt(owner);
    return poseidonHash([ownerBigInt]);
  }));

  const requiredConfirmations = 2;

  const multisig = await MultiSigWallet.deploy(
    ownersPoshash,
    requiredConfirmations,
    // verifier.target
  );

  console.log("MultiSigWallet deployed to:", multisig.target);

  // Send 10000 ether to multisig
  console.log("Sending 1000 ether to the multisig...");
  const tx = await deployer.sendTransaction({
    to: multisig.target,
    value: ethers.parseEther("1000"),
    data: "0x",
  });

  await tx.wait();

  console.log(`Send 1000 ether. Hash: ${tx.hash}`);

  // Create a tx from owner1 and send it via deployer

  let contractSuccessfulAttempts = 0;
  let contractFailedAttempts = 0;
  let verifierContractSuccessfulAttempts = 0;
  let vkeySuccessfulAttempts = 0;
  for (let i = 0; i < 3; i++) {
    
    const to = owners[0];
    const value = hre.ethers.parseEther("1");
    const data = "0x";

    const msgHash = getSolidityKeccak256Hash(to, value, data);

    try {
      console.log("Generating Proof........")
      let createdProof = await createProof(ownersDecomposedPk[0], msgHash, ownersPoshash[0], ownersPoshash[1], ownersPoshash[2]);
      const [proof_0, publicSignals_0] = [createdProof.proof, createdProof.publicSignals];

      const calldata = await snarkjs.groth16.exportSolidityCallData(proof_0, publicSignals_0);
      
      const calldataList = JSON.parse("[" + calldata + "]");


      const vKey = JSON.parse(fs.readFileSync("build/verificationKey.json"));
      const res = await snarkjs.groth16.verify(vKey, publicSignals_0, proof_0);
      if (res) {
        vkeySuccessfulAttempts++;
      }
      const isVerifiedContract = await verifier.verifyProof(calldataList[0], calldataList[1], calldataList[2], calldataList[3]);
      if (isVerifiedContract) {
        verifierContractSuccessfulAttempts++;
      }
      const txHash = await multisig.submitTransaction(to, value, data, calldataList[0], calldataList[1], calldataList[2], calldataList[3]);
      txReceipt = await txHash.wait();
      if (txReceipt) {
        contractSuccessfulAttempts++;
      }
      console.log("Transaction confirmed. Hash: ", txReceipt.hash);
      console.log("++++++++++++++++++++++++++++++++++++++++++++++++++++")
      console.log("Attempt: ", i);
      console.log("Contract successful attempts: ", contractSuccessfulAttempts);
      console.log("Contract failed attempts: ", contractFailedAttempts);
      console.log("Verifier contract successful attempts: ", verifierContractSuccessfulAttempts);
      console.log("Vkey successful attempts:", vkeySuccessfulAttempts);
    } catch (error) {
      console.log("Error: ", error);
      contractFailedAttempts++;

      console.log("++++++++++++++++++++++++++++++++++++++++++++++++++++")
      console.log("Attempt: ", i);
      console.log("Contract successful attempts: ", contractSuccessfulAttempts);
      console.log("Contract failed attempts: ", contractFailedAttempts);
      console.log("Verifier contract successful attempts: ", verifierContractSuccessfulAttempts);
      console.log("Vkey successful attempts:", vkeySuccessfulAttempts);
    }
  }


  // see the stored tx

  // const storedTx = await multisig.transactions(0);
  // console.log("Stored tx: ", storedTx);

  // // // Create a tx from owner2 and send it via deployer
  // createdProof = await createProof(ownersDecomposedPk[1], msgHash, ownersPoshash[0], ownersPoshash[1], ownersPoshash[2]);
  // const [proof_1, publicSignals_1] = [createdProof.proof, createdProof.publicSignals];
  // const calldata_1 = await snarkjs.groth16.exportSolidityCallData(proof_1, publicSignals_1);
  // const calldataList_1 = JSON.parse("[" + calldata_1 + "]");

  // let tx_index = 0;
  // const tx_1 = await multisig.confirmTransaction(tx_index, calldataList_1[0], calldataList_1[1], calldataList_1[2], calldataList_1[3]);
  // txReceipt = await tx_1.wait();
  // console.log("Transaction confirmed. Hash: ", tx_1.transactionHash);

  // execute transaction

}

async function createProof(privkey, msg, addrHash1, addrHash2, addrHash3) {
  return snarkjs.groth16.fullProve(
    {
      privkey: privkey,
      msg: msg,
      addrHash1: addrHash1,
      addrHash2: addrHash2,
      addrHash3: addrHash3,
    },
    "build/multisig_js/multisig.wasm",
    "build/multisig_final.zkey"
  );
}

function getFirstTwoElements(arr) {
  return arr.slice(0, 2);
}

function getSolidityKeccak256Hash(_to, _value, _data) {
  const encodedParams = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "uint256", "bytes"],
    [_to, _value, _data]
  );

  const hash = ethers.keccak256(encodedParams);
  console.log("Hash: ", hash);
  const msgHash = BigInt(hash.toString());
  return msgHash;
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
