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

  console.log("ownersPk: ", ownersPk);

  const ownersPoshash = await Promise.all(owners.map( async (owner) => {
    let ownerBigInt = BigInt(owner);
    return poseidonHash([ownerBigInt]);
  }));

  const requiredConfirmations = 2;

  const multisig = await MultiSigWallet.deploy(
    ownersPoshash,
    requiredConfirmations,
    verifier.target
  );

  console.log("MultiSigWallet deployed to:", multisig.target);

  // Send 10000 ether to multisig
  console.log("Sending 1000 ether to the multisig...");
  const tx = await deployer.sendTransaction({
    to: multisig.target,
    value: ethers.parseEther("1000"),
    data: "0x",
  });

  console.log("Transaction sent. Waiting for confirmation...");
  await tx.wait();

  console.log(`Transaction confirmed. Hash: ${tx.hash}`);

  // Create a tx from owner1 and send it via deployer

  const to = owners[0];
  const value = hre.ethers.parseEther("1");
  const data = "0x";

  const msgHash = getSolidityKeccak256Hash(to, value, data);
  let createdProof = await createProof(ownersDecomposedPk[0], msgHash, ownersPoshash[0], ownersPoshash[1], ownersPoshash[2]);
  const [proof_0, publicSignals_0] = [createdProof.proof, createdProof.publicSignals];

  console.log("Proof: ", proof_0);
  console.log("Public signals: ", publicSignals_0);
  const calldata = await snarkjs.groth16.exportSolidityCallData(proof_0, publicSignals_0);
  
  const calldataList = JSON.parse("[" + calldata + "]");
  console.log("Calldata: ", calldata);

  const vKey = JSON.parse(fs.readFileSync("build/vkey.json"));
  const res = await snarkjs.groth16.verify(vKey, publicSignals_0, proof_0);

  console.log("verification result: ", res);

  const txHash = await multisig.submitTransaction(to, value, data, calldataList[0], calldataList[1], calldataList[2], calldataList[3]);
  txReceipt = await txHash.wait();
  console.log("Transaction confirmed. Hash: ", txReceipt.txHash);

  // see the stored tx

  const storedTx = await multisig.transactions(0);
  console.log("Stored tx: ", storedTx);

  // // Create a tx from owner2 and send it via deployer

  // console.log("ownersDecomposedPk[1]:", ownersDecomposedPk[1]);
  // createdProof = await createProof(ownersDecomposedPk[1], msgHash, ownersPoshash[0], ownersPoshash[1], ownersPoshash[2]);
  // const [proof_1, publicSignals_1] = [createdProof.proof, createdProof.publicSignals];
  // let tx_index = 0;
  // const txHash_1 = await multisig.confirmTransaction(tx_index, getFirstTwoElements(proof_1.pi_a), getFirstTwoElements(proof_1.pi_b), getFirstTwoElements(proof_1.pi_c), publicSignals_1);
  // txReceipt = await txHash_1.wait();
  // console.log("Transaction confirmed. Hash: ", txReceipt.txHash);

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
