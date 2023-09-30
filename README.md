# qip-wallet-lib
A  javascript bitcoin library used to build qip wallet 

```js
 import {
  createAddress, 
  createPassPhrase, 
  createSingleTransaction, 
  createTransaction, 
  getAddressType ,
  getFeeRate ,
  getUtxo, 
  getTransactionDetails, 
  getInputData, 
  signTransaction, 
  getTransactionSize, 
  accountKeys, 
  getAllAddress, 
  hasInscription ,
  getAllUtxo,
  genQrCode
} from "./bitcoin/utils.js"



//return passPhrase as string
// {
//    passPhrase: "powder hover float rug home mercy trip deliver object ozone grant copy"
// }
const createWalletPassPhrase = ()=> {
    try{
        return createPassPhrase()
    }catch(e){
        console.log(e.message)
    }
}

//returns an object with the private and wif keys
//{
//    privateKey: 'e9430126753f24bff22520e1cd5ca9fa',
//    wif: 'cQyU2ay451EPSrDYHdNMYHWaGFzp7Euwa6nnEXk5FXqxT6sz3A99'
//}
const getAccountKeys = (passPhrase, networkName, accountPath) => {
    try{
        return accountKeys({passPhrase: passPhrase, networkName: networkName, path: accountPath})
    }catch(e){
        console.log(e.message)
    }
}

//returns an object with address and pubKeyScript(buffer) based on address type spesified
//key can be wif or private, add whichever should be spesified as the prop passed to the create address method
// {
//     address: 'tb1q92s4d7f890y80q4nts72hcx8ssvyh44dj037qv',
//     script: <Buffer 00 14 2a a1 56 f9 27 2b c8 77 82 b3 5c 3c ab e0 c7 84 18 4b d6 ad>
// }

const getAddress = (key, networkName, addressType) => {
    try{
        return createAddress({privateKey: key, networkName: networkName, addressType: addressType})
    }catch(e){
        console.log(e.message)
    }
}

//returns an array of all available utxo: can be used with coin control, viewing and locking utxos
// [
//     {
//       txid: '708dd00f61eb5bc582f8293c0f121d695120a8441174612600ca2afea627f50b',
//       vout: 1,
//       value: 214255
//     },
//     {
//       txid: 'c78420f03dc363d4764ffc0d8b5fe5d77efe7c2463719ddd6d25aa4ae40733f8',
//       vout: 0,
//       value: 1000
//     }
// ]
const getAllUtxo = async (address, networkName) => {
    try{
        return await getUtxo({networkName:networkName, address: address})
    }catch(e){
        console.log(e.message)
    }
}

//this is to be used to create a transaction objec. it takes input which is an arrya of utxo and output which is an arrya 
//the contains the receiver address and the value. This should be used for sending multiple.
//input:[{txid:"27bfa9c4164744e2a8f245de93100495974d812612441061189ab0904b235c10", vout:0, value:24606}, {txid:"0f53820e0443bf49489040b00663b2920d4376165a0843a0210b1ba0d11a9a81", vout:2, value:24991}], 
//output:[{address:"bc1padzcq6u7jh833v7gwgq7dlzqqmhuyp0plhm20f0nnjgmg0rxjjqqsq9a5t", value:10000}, {address:"1KdREt8JvPcr4JSN1kFVbQ6jKLVprBFVnC", value:15000}],
// returns a transaction object to be signed
// {
//     input: [
//       {
//         hash: '27bfa9c4164744e2a8f245de93100495974d812612441061189ab0904b235c10',
//         index: 0,
//         witnessUtxo: [Object]
//       },
//       {
//         hash: '0f53820e0443bf49489040b00663b2920d4376165a0843a0210b1ba0d11a9a81',
//         index: 2,
//         witnessUtxo: [Object]
//       }
//     ],
//     output: [
//       {
//         address: 'bc1padzcq6u7jh833v7gwgq7dlzqqmhuyp0plhm20f0nnjgmg0rxjjqqsq9a5t',
//         value: 10000
//       },
//       { address: '1KdREt8JvPcr4JSN1kFVbQ6jKLVprBFVnC', value: 15000 },
//       {
//         address: 'bc1q92s4d7f890y80q4nts72hcx8ssvyh44dcf2dml',
//         value: 20397
//       }
//     ],
//     transactionFee: 4200,
//     transactionSize: { txVBytes: 255, txBytes: 420, txWeight: 1020 },
//     totalSpent: 29200
//   }
const createNewTransaction = async (input, output, key, addressType,networkName, feeRate) => {
    try{
        createTransaction({
              input:input,
              output: output,
              //wif: key
              privateKey: key,
              addressType:addressType,
              networkName:networkName,
              feeRate: feeRate
            })
    }catch(e){
        console.log(e.message)
    }
}
```
