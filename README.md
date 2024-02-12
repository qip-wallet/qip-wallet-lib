# qip-wallet-lib
Documentation for the QIP Wallet Library
qip-wallet-lib provides set of tools for working with Bitcoin transactions and keys. It is written in javascript and works in node.js enviroment

## Features
- Create HD wallet
- Create transaction
- Sign transaction and PSBT
- Create inscriptions with special sat

## Installation
```js
npm install qip-wallet-lib
```

## Usage
```js
/**
 * Wallet
 */
const {wallet} = require('qip-wallet-lib');

// Create a new wallet
const passPhrase = wallet.createPassPhrase();
console.log("passPhrase: ",passPhrase);

// Create a new address
const accountKeys = wallet.accountKeys({passPhrase: passPhrase, networkName: 'testnet', path:0});
console.log("accountKeys: ",accountKeys);

// Create a new address
const address = wallet.getAllAddress({privateKey: accountKeys.privateKey, networkName: 'testnet'});

// Create a new transaction
const tx = wallet.createTransaction2({
    input:[{txid:"133c3dcf862b1ed6a01efaa70da27acbf9449bc766ef268edaac4a711be3eb36", vout:1, value:8332}], 
    output:[{address:"tb1q4myftf8sc0rzpwnmluaq06ygykprq9ld0fz60c", value:550}],
    publicKey: "e6c357476d31cfd13b8e75d5b29b94cbff062d489a7965baaabf0bddd68db2c0",
    addressType:"taproot",
    networkName:"testnet",
    feeRate: 10,
        change: "tb1pump4w3mdx88azwuwwh2m9xu5e0lsvt2gnfuktw42hu9am45dktqq3rfjtj",
    });

console.log("tx: ",tx);

// Sign transaction
const signedTx = wallet.signTransaction({
    psbt: {psbtBase64: "cHNidP8BAH0CAAAAATbr4xtxSqzajibvZsebRPnLeqINp/oeoNYeK4bPPTwTAQAAAAD/////AiYCAAAAAAAAFgAUrsiVpPDDxiC6e/86B+iIJYIwF+1KHQAAAAAAACJRIObDV0dtMc/RO4511bKblMv/Bi1Imnlluqq/C93WjbLAAAAAAAABASuMIAAAAAAAACJRIObDV0dtMc/RO4511bKblMv/Bi1Imnlluqq/C93WjbLAARcg5sNXR20xz9E7jnXVspuUy/8GLUiaeWW6qr8L3daNssAAAAA="}, privateKey:accountKeys.privateKey, 
    networkName: 'testnet'
    });

console.log("signedTx: ",signedTx);

/**
 * Inscription
 */

const {inscription} = require('qip-wallet-lib');

// Create a new inscription

//These are optional parameters used to create inscription
const options = {   
    metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz"},
    satTx: {
        txid: "9225058961e6e73273d9b58748dbcd5f832a3f0cebbb88daf424e0c15314ab56",
        vout: 0,
        value: 1000
    }
}

//get inscription keyPair
const inscriptionKeyPair = inscription.getKeyPair({networkName: 'testnet'});
console.log("inscriptionKeyPair: ",inscriptionKeyPair);

//get inscription initlization data
//this returns all the data required to create inscription including the funding address
const initData = getInitData({networkName: "testnet", privateKey: inscriptionKeyPair.privateKey});
console.log("initData: ",initData);


//get all inscription
//this returns an array of inscriptions and the total cost of inscriptions
let filePaths = [`${process.cwd()}/test.png`]
let feeRate = 21
let padding = 550

const inscriptionData = inscription.getInscriptions({
    filePaths: filePaths, 
    publicKey: inscriptionKeyPair.publicKey, 
    networkName: "testnet", 
    feerate: feeRate, 
    padding: padding, 
    options: options 
    });

console.log("inscriptionData: ",inscriptionData);

/**
 now you fund the address from initData.fundingAddress with the value of inscriptionData.total_fees
 NB: If satTx is provided in options, the sat utxo has to be in the funding address as well
*/

//split funded utxo to different inscription addresses
//It returns a signed transaction to be broadcasted in hexadecimal(HEX) format, as well as the transaction id(txid)
const splitFunds = inscription.splitFunds({
    filePaths: filePaths, 
    privateKey: inscriptionKeyPair.privateKey, 
    networkName: "testnet", 
    feerate: feeRate, 
    padding: padding, 
    options: options
    })

console.log("splitFunds: ",splitFunds);

//create inscription(s)
//It returns an array of signed inscription transaction to be broadcasted in hexadecimal(HEX) format, 
//their transaction ids as well as the inscriptiond id.
const createInscription = inscription.createInscription({
    filePaths:filePaths, 
    privateKey:privateKey, 
    receiveAddress:"tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", 
    networkName:"testnet", 
    feerate:feeRate, 
    padding:padding, 
    options:options
    })

console.log("createInscription: ",createInscription);
```





