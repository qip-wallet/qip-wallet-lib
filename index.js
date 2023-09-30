import bitcore from "bitcore-lib";
import Mnemonic from "bitcore-mnemonic";
import {
    initEccLib,
    networks,
    crypto,
    payments,
    Psbt,
} from "bitcoinjs-lib";
import * as tinysecp from "tiny-secp256k1";
import  { ECPairFactory } from "ecpair";
import mempoolJS from "@mempool/mempool.js";
import {bech32m, bech32} from 'bech32';


initEccLib(tinysecp);
const ECPair = ECPairFactory(tinysecp);

export default class Bitcoin {

    createPassPhrase = () => {
        try{
        let passPhrase = new Mnemonic(Mnemonic.Words.ENGLISH).toString();
        return{passPhrase: passPhrase}
        }catch(e){
        throw new Error(e.message);
        }
  }

  accountKeys = (config)=>{
    try{
      const network = this.getNetwork(config.networkName);
      let code = new Mnemonic(config.passPhrase)
      let xpriv = code.toHDPrivateKey(config.passPhrase).derive(`m/44/0/0/0/${config.path}`);
      let privateKey = xpriv.privateKey.toString();
      let keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey.slice(0, 32)), {network});
      
      return {
        privateKey: keyPair.privateKey.toString(),
        wif: keyPair.toWIF()
      };
    }catch(e){
      throw new Error(e.message)
    }
  };

  createAddress = (config) => {
    try {
      const network = this.getNetwork(config.networkName);
      let keyPair;
      if(config.privateKey){
        keyPair = ECPair.fromPrivateKey(Buffer.from(config.privateKey), {network})
      }else if(config.wif){
        keyPair = ECPair.fromWIF(config.wif, network)
      }
      let address;
      let script

      switch (config.addressType){
        case "taproot":
          const tweakedSigner = this.tweakSigner(keyPair, { network });
          const p2tr = payments.p2tr({
          pubkey: this.toXOnly(tweakedSigner.publicKey),
          network,
        });
        address = p2tr.address ?? "";
        script = p2tr.output;
        break;
        case "legacy":
          const p2pkh = payments.p2pkh({ pubkey: keyPair.publicKey, network: network })
          address = p2pkh.address ?? "";
          script = p2pkh.output;
        break;
        case "segwit":
          const p2wpkh = payments.p2wpkh({ pubkey: keyPair.publicKey , network: network})
          address = p2wpkh.address ?? "";
          script = p2wpkh.output;
          break
      }
      return { address: address, script: script};
    } catch (e) {
      console.log(e);
    }
  };


  init = async (network) => {
    const {
      bitcoin: { addresses, fees, transactions },
    } = mempoolJS({
      hostname: "mempool.space",
      network: network,
    });
  
    return { addresses, fees, transactions };
  };

  getAddressType = ({address, networkName}) => {
    try{
      let addressType
      switch (networkName){
        case "mainnet":
          addressType = this.mainnetAddressType(address, networkName)
          break
        case "testnet":
          addressType = this.testnetAddressType(address)
          break
      }

      if(addressType == null) return `invalid ${networkName} address`
      return addressType
    }catch(e){
      throw new Error(e.message)
    }
  }

  //Transaction Methods
   getUtxo = async ({networkName, address}) => {
    try{
      const { addresses } = await this.init(networkName);
      let response = await addresses.getAddressTxsUtxo({ address: address });
      let utxos = response.map(x => {
        return{
          txid: x.txid,
          vout: x.vout,
          value: x.value
        }
      })
      return utxos
    }catch(e){
      throw new Error(e.message)
    }
  }

  getFeeRate = async (networkName)=> {
    try{
      let {fees} = await this.init(networkName)
      const feesRecommended = await fees.getFeesRecommended();
      return feesRecommended;
    }catch(e){
      throw new Error(e.message)
    }
  }

  getTransactionDetails = async ({txid,networkName}) => {
    try{
      let {transactions} = await this.init(networkName)
      let txDetails = await transactions.getTx({txid: txid})
      return txDetails
    }catch(e){
      throw new Error(e.message)
    }
  }

  //input = [{txid: "", vout: 2, value: 20000}, {txid: "", vout: 0, value: 20000}]
  //output = [{address: "", value:32000}]
   createTransaction = async ({input, output, addressType, networkName, feeRate, privateKey, wif }) => {
    try{ 
      let inputData = await this.getInputData(addressType,input,networkName,privateKey,wif)
      let outputData = output
      let totalAvailable = 0;
      let toSpend = 0;
      let changeAddress;
      let outPutFeeDetails = new Map();
      let outFeeData = [];
      if(privateKey){
        changeAddress = this.createAddress({addressType:addressType, networkName:networkName, privateKey:privateKey}).address;
        let changeAddressType = this.getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }else if(privateKey){
        changeAddress = this.createAddress({addressType:addressType, networkName:networkName, wif:wif}).address
        let changeAddressType = this.getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }

      input.forEach(x => {
        totalAvailable = totalAvailable + x.value
      })

      output.forEach(x =>{
        let outputType = this.getAddressType({address: x.address, networkName:networkName})
        toSpend = toSpend + x.value
        if(!outPutFeeDetails.has(outputType)){
          outPutFeeDetails.set(outputType,1)
        }else{
          outPutFeeDetails.set(outputType, outPutFeeDetails.get(outputType)+1)
        }
      })

      outPutFeeDetails.forEach((value, key) => {
        outFeeData.push({
          outputType: key,
          count: value
        })
      })

      let txSize = this.getTransactionSize({input: input.length, output:outFeeData, addressType: addressType})
      let txFee = txSize.txBytes * feeRate
      console.log(txFee)
      if(totalAvailable - txFee - toSpend <= 550) return new Error("not enough sats in input for transaction")
      outputData.push({address:changeAddress, value: totalAvailable - toSpend - txFee})
      
      return {
        input: inputData,
        output: outputData,
        transactionFee: txFee,
        transactionSize: txSize,
        totalSpent: toSpend + txFee
      }
    }catch(e){
      throw new Error(e.message)
    }
  }

  createSingleTransaction = async ({receiver,amount,addressType,networkName,feeRate,privateKey, wif}) => {
    try{
      //let outputData = output
      let input = [];
      let output = []
      let availableInput = 0
      let changeAddress;
      let outPutFeeDetails = new Map();
      let outFeeData = [];
      
      output.push({
        address:receiver,
        value:amount
      })
      
      if(privateKey){
        changeAddress = this.createAddress({addressType:addressType, networkName:networkName, privateKey:privateKey}).address;
        let changeAddressType = this.getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }else if(wif){
        changeAddress = this.createAddress({addressType:addressType, networkName:networkName, wif:wif}).address
        let changeAddressType = this.getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }

      outPutFeeDetails.forEach((value, key) => {
        outFeeData.push({
          outputType: key,
          count: value
        })
      })


      let utxos = await this.getUtxo({networkName:networkName, address:changeAddress})
      
      for(let i = 0; i < utxos.length; i++){
        let inputCount = 0
        if(input.length > 0){
          inputCount = input.length
        }
        availableInput = availableInput + utxos[i].value
        let txSize = this.getTransactionSize({input: inputCount, output:outFeeData, addressType: addressType})
        let txFee = txSize.txBytes * feeRate
        if(availableInput - txFee - amount < 550){
          input.push({
            txid: utxos[i].txid,
            vout: utxos[i].vout,
            value: utxos[i].value
          })
          continue;
        }else{
          input.push({
            txid: utxos[i].txid,
            vout: utxos[i].vout,
            value: utxos[i].value
          })
          break;
        }
      }

      let txSize = this.getTransactionSize({input: input.length, output:outFeeData, addressType: addressType})
      let txFee = txSize.txBytes * feeRate
      if(availableInput < txFee + amount + 550) throw new Error("available balance is not sufficient for transaction")
      let transactionDetails;

      if(privateKey){
          transactionDetails = await this.createTransaction({
          input:input, 
          output:output, 
          addressType:addressType, 
          networkName:networkName,
          feeRate:feeRate,
          privateKey
        })
      }else if(wif){
        transactionDetails = await this.createTransaction({
          input:input, 
          output:output, 
          addressType:addressType, 
          networkName:networkName,
          feeRate:feeRate,
          privateKey
        })
      }
      return transactionDetails;
    }catch(e){
      throw new Error(e.message)
    }
  }

  signTransaction = (transaction) => {
    try{
      const network = this.getNetwork(transaction.networkName)
      let keyPair;
      if(transaction.privateKey){
        keyPair = ECPair.fromPrivateKey(Buffer.from(transaction.privateKey), {network})
      }else if(transaction.wif){
        keyPair = ECPair.fromWIF(transaction.wif, network)
      }
      if(transaction.addressType === "taproot"){
        keyPair = this.tweakSigner(keyPair, network)
      }
      let psbt = new Psbt({network})
      .addInputs(transaction.input)
      .addOutputs(transaction.output)
      .signAllInputs(keyPair)
      .finalizeAllInputs();
      const txs = psbt.extractTransaction();
      const txHex = txs.toHex();

      return {
        txHex: txHex,
        signedTransaction:txs
      }
    }catch(e){
      throw new Error(e.message)
    }
  }

  //input = [{txid: "", vout: 2, value: 20000}, {txid: "", vout: 0, value: 20000}]
 getInputData = async (addressType, input, networkName, privateKey, wif) => {
    try{
      let{transactions} = await this.init(networkName)
      let network = this.getNetwork(networkName)
      let keyPair;
      let inData;
      let inputTx = await Promise.all(input.map(async(item)=>{
        return {tx: await transactions.getTx({txid:item.txid}), vout: item.vout}
      }))
      
      switch (addressType){
        case "legacy":
          let tx = await Promise.all(input.map(async(x)=>{
            return {txHex: Buffer.from(await transactions.getTxHex({txid:x.txid}), "hex"), hash: x.txid, index:x.vout}
          }))
          inData = tx.map(async (x) =>{
            return {
              hash:x.hash,
              index:x.index,
              nonWitnessUtxo: x.txHex
            }
          })
          break
        case "segwit":
          inData = inputTx.map((x) =>{
            return {
              hash:x.tx.txid,
              index:x.vout,
              witnessUtxo: {value: x.tx.vout[x.vout].value, script: Buffer.from(x.tx.vout[x.vout].scriptpubkey, "hex")}
            }
          })
          break
        case "taproot":
          if(privateKey){
            keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey), {network})
          }else if(wif){
            keyPair = ECPair.fromWIF(wif, network)
          }
          let tweakedSigner = this.tweakSigner(keyPair, { network });
          inData = inputTx.map((x) =>{
            return {
              hash:x.tx.txid,
              index:x.vout,
              witnessUtxo: {value: x.tx.vout[x.vout].value, script: Buffer.from(x.tx.vout[x.vout].scriptpubkey, "hex")},
              tapInternalKey: this.toXOnly(tweakedSigner.publicKey)
            }
          })
          break
      }
      return inData
    }catch(e){

    }
  }

  //output = [{outputType: "P2TR", count: 2}, {outputType: "P2PKH", count: 2}]
 getTransactionSize = ({input, output, addressType}) => {
    try{
      const P2PKH_IN_SIZE = 148;
      const P2PKH_OUT_SIZE = 34;

      const P2SH_OUT_SIZE = 32;
      const P2SH_P2WPKH_IN_SIZE = 90.75;

      const P2WPKH_IN_SIZE = 67.75;
      const P2WPKH_OUT_SIZE = 31;
      
      const P2TR_OUT_SIZE = 43;
      const P2TR_IN_SIZE = 57.25;
    
      let p2pkh_output_count = 0
      let p2wpkh_output_count = 0
      let p2tr_output_count = 0
      let p2sh_output_count = 0

      output.forEach(element => {
        if(element.outputType === "P2TR"){
          p2tr_output_count = element.count
        }else if(element.outputType === "P2WPKH"){
          p2wpkh_output_count = element.count
        }else if(element.outputType === "P2TR"){
          p2tr_output_count = element.count
        }else if(element.outputType === "P2PKH"){
          p2pkh_output_count = element.count
        }
      });
      
      
      let inputScript;
      let inputSize = 0;
      let inputWitness = 0
      switch (addressType){
        case "taproot":
          inputScript = "P2TR"
          inputSize = P2TR_IN_SIZE
          inputWitness = 108
          break
        case "segwit":
          inputScript = "P2WPKH"
          inputSize = P2WPKH_IN_SIZE
          inputWitness = 108
          break
        case "legacy":
          inputScript = "P2PKH"
          inputSize = P2PKH_IN_SIZE
      }

      let txVBytes = this.getTxOverheadVBytes(inputScript, input, output.length) +
                    inputSize * input +
                    P2PKH_OUT_SIZE * p2pkh_output_count +
                    P2WPKH_OUT_SIZE * p2wpkh_output_count +
                    P2TR_OUT_SIZE * p2tr_output_count + 
                    P2SH_OUT_SIZE * p2sh_output_count;
        txVBytes = Math.ceil(txVBytes);

        var txBytes = Math.ceil(this.getTxOverheadExtraRawBytes(inputScript, input) + txVBytes + (inputWitness * input) * 3 / 4);
        var txWeight = Math.ceil(txVBytes * 4);

        return {txVBytes:txVBytes, txBytes:txBytes, txWeight:txWeight}
    }catch(e){
      throw new Error(e.message)
    }
  }

  getNetwork = (networkName) => {
    if (networkName === "mainnet") {
      return networks.bitcoin;
    } else if (networkName === "testnet") {
      return networks.testnet;
    }
  };

  //Address validation helpers
  mainnetAddressType = (address, networkName) => {
    try{
        // Remove leading and trailing whitespace
        const trimmedAddress = address.trim();      
        
        // Check for P2PKH (Pay-to-Public-Key-Hash) addresses
        if (/^1[0-9A-Za-z]{25,34}$/.test(trimmedAddress)) {
          return 'P2PKH';
        }
      
        // Check for P2SH (Pay-to-Script-Hash) addresses
        if (/^3[0-9A-Za-z]{25,34}$/.test(trimmedAddress)) {
          return 'P2SH';
        }

        if(this.checkTaproot(trimmedAddress, networkName) == true ){
          return "P2TR"
        }

        if(this.checkSegwit(trimmedAddress, networkName) == true){
          return "P2WPKH"
        }

        return null;
    }catch(e){
      throw new Error(e.message)
    }
  }

  testnetAddressType = (address) => {
    try{
        const trimmedAddress = address.trim();

        if (/^m[0-9A-Za-z]{25,34}$/.test(trimmedAddress)) {
          return 'P2PKH';
        }
    
        if (/^2[0-9A-Za-z]{25,34}$/.test(trimmedAddress)) {
          return 'P2SH';
        }

        if (/^(tb1|[mn2])[a-zA-HJ-NP-Z0-9]{25,39}$/.test(trimmedAddress)) {
          if (trimmedAddress.startsWith('tb1q')) {
            return 'P2WPKH';
          }
          if (trimmedAddress.startsWith('tb1p')) {
            return 'P2TR';
          }
        }
        return null;
    }catch(e){
      throw new Error(e.message)
    }
  }


  checkTaproot = (address, networkName) => {
    try {
      if(networkName === "mainnet" && address.startsWith("tb1q")) return false
      if(networkName === "mainnet" && address.startsWith("tb1p")) return false
      let isTaproot = bech32m.decode(address).words;
      if(isTaproot[0] === 0x1) return true
    } catch (error) {
      return false;
    }
  }

  checkSegwit = (address, networkName) => {
    try {
      if(networkName === "mainnet" && address.startsWith("tb1q")) return false
      if(networkName === "mainnet" && address.startsWith("tb1p")) return false
      let isSegwit = bech32.decode(address).words;
      if(isSegwit[0] === 0x0) return true
    } catch (error) {
      return false;
    }
  }

  //Taproot Tweek Helpers
  tweakSigner(signer, opts) {
    let privateKey = signer.privateKey;
    if (!privateKey) {
      throw new Error("Private key is required for tweaking signer!");
    }
    if (signer.publicKey[0] === 3) {
      privateKey = tinysecp.privateNegate(privateKey);
    }
  
    const tweakedPrivateKey = tinysecp.privateAdd(
      privateKey,
      this.tapTweakHash(this.toXOnly(signer.publicKey), opts.tweakHash)
    );
    if (!tweakedPrivateKey) {
      throw new Error("Invalid tweaked private key!");
    }
  
    return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
      network: opts.network,
    });
  }
  
  tapTweakHash(pubKey, h) {
    return crypto.taggedHash(
      "TapTweak",
      Buffer.concat(h ? [pubKey, h] : [pubKey])
    );
  }
  
  toXOnly(pubkey) {
    return pubkey.subarray(1, 33);
  }
  
  // Transaction Size Helpers
  getSizeOfScriptLengthElement = (length) => {
    if (length < 75) {
      return 1;
    } else if (length <= 255) {
      return 2;
    } else if (length <= 65535) {
      return 3;
    } else if (length <= 4294967295) {
      return 5;
    } else {
      alert('Size of redeem script is too large');
    }
  }
  
  getSizeOfVarInt =(length) =>{
    if (length < 253) {
      return 1;
    } else if (length < 65535) {
      return 3;
    } else if (length < 4294967295) {
      return 5;
    } else if (length < 18446744073709551615) {
      return 9;
    } else {
      throw new Error("Invalid var int")
    }
  }

  getTxOverheadVBytes = (input_script, input_count, output_count) =>{
    if (input_script == "P2PKH" || input_script == "P2SH") {
      var witness_vbytes = 0;
    } else { // Transactions with segwit inputs have extra overhead
      var witness_vbytes = 0.25                 // segwit marker
                        + 0.25                  // segwit flag
                        + input_count / 4;      // witness element count per input
    }

    return 4 // nVersion
          + this.getSizeOfVarInt(input_count) // number of inputs
          + this.getSizeOfVarInt(output_count) // number of outputs
          + 4 // nLockTime
          + witness_vbytes;
  }

  getTxOverheadExtraRawBytes = (input_script, input_count) =>{
    // Returns the remaining 3/4 bytes per witness bytes
    if (input_script == "P2PKH" || input_script == "P2SH") {
      var witness_bytes = 0;
    } else { // Transactions with segwit inputs have extra overhead
      var witness_bytes = 0.25             // segwit marker
                       + 0.25              // segwit flag
                       + input_count / 4;  // witness element count per input
    }

    return witness_bytes * 3;
  }
}

//let bitcoin = new Bitcoin()
//console.log(bitcoin.createPassPhrase())
//console.log(bitcoin.createAddress({privateKey: "96346ed8a28b9c0dde05604fcb6169df", networkName:"testnet", addressType: "segwit"}))
//bitcoin.getFeeRate("mainnet").then(res=> console.log(res)).catch()
//console.log(bitcoin.getAddressType({address:"1KdREt8JvPcr4JSN1kFVbQ6jKLVprBFVnC",networkName: "mainnet"}))
//console.log(bitcoin.getTransactionSize({input:5, output:[{outputType: "P2TR", count: 2},{outputType: "P2PKH", count: 2}], addressType: "segwit"}))
//bitcoin.getInputData("legacy", [{txid:"78beab4a2b940fd0dfac7987cd0acd89fdb862545f795a7ef4f7cd679251fb72", vout:1}], "mainnet", {privateKey: "96346ed8a28b9c0dde05604fcb6169df"}).then(res=>{console.log(res)}).catch()
//bitcoin.getUtxo({networkName:"testnet", address:"tb1q92s4d7f890y80q4nts72hcx8ssvyh44dj037qv"}).then(res=>console.log(res)).catch()
// bitcoin.createTransaction({
//   input:[{txid:"27bfa9c4164744e2a8f245de93100495974d812612441061189ab0904b235c10", vout:0, value:24606}, {txid:"0f53820e0443bf49489040b00663b2920d4376165a0843a0210b1ba0d11a9a81", vout:2, value:24991}], 
//   output:[{address:"bc1padzcq6u7jh833v7gwgq7dlzqqmhuyp0plhm20f0nnjgmg0rxjjqqsq9a5t", value:10000}, {address:"1KdREt8JvPcr4JSN1kFVbQ6jKLVprBFVnC", value:15000}],
//   privateKey: "96346ed8a28b9c0dde05604fcb6169df",
//   addressType:"segwit",
//   networkName:"mainnet",
//   feeRate: 10
// }).then(res=> console.log(res)).catch()


//input
//[{txid:"27bfa9c4164744e2a8f245de93100495974d812612441061189ab0904b235c10", vout:0, value:24606}, {txid:"0f53820e0443bf49489040b00663b2920d4376165a0843a0210b1ba0d11a9a81", vout:2, value:24991}]
//[{address:"bc1padzcq6u7jh833v7gwgq7dlzqqmhuyp0plhm20f0nnjgmg0rxjjqqsq9a5t", value:10000}, {address:"1KdREt8JvPcr4JSN1kFVbQ6jKLVprBFVnC", value:20000}]


// bitcoin.createSingleTransaction({
//   receiver:"tb1q92s4d7f890y80q4nts72hcx8ssvyh44dj037qv",
//   amount: 1000,
//   privateKey: "96346ed8a28b9c0dde05604fcb6169df",
//   addressType:"taproot",
//   networkName:"testnet",
//   feeRate: 10
// }).then(res=> console.log(res)).catch()