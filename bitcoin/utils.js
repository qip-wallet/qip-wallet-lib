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
import QRCode from 'qrcode'



initEccLib(tinysecp);
const ECPair = ECPairFactory(tinysecp);


export function createPassPhrase () {
    try{
    let passPhrase = new Mnemonic(Mnemonic.Words.ENGLISH).toString();
    return{passPhrase: passPhrase}
    }catch(e){
    throw new Error(e.message);
    }
  }

  export function accountKeys({networkName, passPhrase, path}) {
    try{
      const network = getNetwork(networkName);
      let code = new Mnemonic(passPhrase)
      let xpriv = code.toHDPrivateKey(passPhrase).derive(`m/44/0/0/0/${path}`);
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

  export function createAddress ({privateKey, wif, networkName, addressType}) {
    try {
      const network = getNetwork(networkName);
      let keyPair;
      if(privateKey){
        keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey), {network})
      }else if(wif){
        keyPair = ECPair.fromWIF(wif, network)
      }
      let address;
      let script

      switch (addressType){
        case "taproot":
          const tweakedSigner = tweakSigner(keyPair, { network });
          const p2tr = payments.p2tr({
          pubkey: toXOnly(tweakedSigner.publicKey),
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
      throw new Error(e.message)
    }
  };


  export function getAllAddress ({privateKey, wif, networkName}) {
    try {
      let addressTypes = ["taproot", "segwit", "legacy"];
      
      let addressList = addressTypes.map((x)=> {
        let addressDetails
        if(privateKey){
          addressDetails = createAddress({privateKey: privateKey, networkName:networkName, addressType:x})
        }else if(config.wif){
          addressDetails = createAddress({wif: wif, networkName:networkName, addressType:x})
        }
        return {
          address: addressDetails.address,
          addressType: x,
          scriptType: getAddressType({address:addressDetails.address, networkName:networkName})
        }
      })

      return addressList;
    }catch(e){
      throw new Error(e.message)
    }
  }


  export async function init (network) {
    const {
      bitcoin: { addresses, fees, transactions },
    } = mempoolJS({
      hostname: "mempool.space",
      network: network,
    });
  
    return { addresses, fees, transactions };
  };

  export function getAddressType ({address, networkName}) {
    try{
      let addressType
      switch (networkName){
        case "mainnet":
          addressType = mainnetAddressType(address, networkName)
          break
        case "testnet":
          addressType = testnetAddressType(address)
          break
      }

      if(addressType == null) return `invalid ${networkName} address`
      return addressType
    }catch(e){
      throw new Error(e.message)
    }
  }

  //Transaction Methods
  export async function getUtxo ({networkName, address}){
    try{
      const { addresses } = await init(networkName);
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

  export async function getFeeRate (networkName) {
    try{
      let {fees} = await init(networkName)
      const feesRecommended = await fees.getFeesRecommended();
      return feesRecommended;
    }catch(e){
      throw new Error(e.message)
    }
  }

  export async function getTransactionDetails  ({txid,networkName}) {
    try{
      let {transactions} = await init(networkName)
      let txDetails = await transactions.getTx({txid: txid})
      return txDetails
    }catch(e){
      throw new Error(e.message)
    }
  }

  //input = [{txid: "", vout: 2, value: 20000}, {txid: "", vout: 0, value: 20000}]
  //output = [{address: "", value:32000}]
  export async function createTransaction ({input, output, addressType, networkName, feeRate, privateKey, wif }) {
    try{ 
      let inputData = await getInputData(addressType,input,networkName,privateKey,wif)
      let outputData = output
      let totalAvailable = 0;
      let toSpend = 0;
      let changeAddress;
      let outPutFeeDetails = new Map();
      let outFeeData = [];
      if(privateKey){
        changeAddress = createAddress({addressType:addressType, networkName:networkName, privateKey:privateKey}).address;
        let changeAddressType = getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }else if(privateKey){
        changeAddress = createAddress({addressType:addressType, networkName:networkName, wif:wif}).address
        let changeAddressType = getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }

      input.forEach(x => {
        totalAvailable = totalAvailable + x.value
      })

      output.forEach(x =>{
        let outputType = getAddressType({address: x.address, networkName:networkName})
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

      let txSize = getTransactionSize({input: input.length, output:outFeeData, addressType: addressType})
      let txFee = txSize.txBytes * feeRate
      let changeAmount = totalAvailable - txFee - toSpend
      if(toSpend + txFee > totalAvailable) {
        throw new Error("not enough utxo balance for transactions")
      }else if(changeAmount < 550 && changeAmount > 0){
        let inputData = await getInputData(addressType, input, networkName, privateKey, wif)
        let signedTx = signTransaction({networkName:networkName, privateKey:privateKey, wif:wif, addressType:addressType, input:inputData, output:output})
        return {
          txHex: signedTx.txHex,
          tx: signedTx.signedTransaction,
          fee: txFee,
          satSpent: toSpend + txFee,
          txSize: txSize,
        }
      }else{
        outputData.push({address:changeAddress, value: totalAvailable - toSpend - txFee})
        let inputData = await getInputData(addressType, input, networkName, privateKey, wif)
        let signedTx = signTransaction({networkName:networkName, privateKey:privateKey, wif:wif, addressType:addressType, input:inputData, output:output})
        return {
          txHex: signedTx.txHex,
          tx: signedTx.signedTransaction,
          fee: txFee,
          satSpent: toSpend + txFee,
          txSize: txSize
        }
      }
    }catch(e){
      throw new Error(e.message)
    }
  }

  export async function createSingleTransaction ({receiver,amount,addressType,networkName,feeRate,privateKey, wif}) {
    try{
      //let outputData = output
      let input = [];
      let output = []
      let availableInput = 0
      let changeAddress;
      let outPutFeeDetails = new Map();
      let outFeeData = [];
      
      let receiverAddressType = getAddressType({address:receiver, networkName:networkName})
      if(privateKey){
        changeAddress = createAddress({addressType:addressType, networkName:networkName, privateKey:privateKey}).address;
        let changeAddressType = getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }else if(wif){
        changeAddress = createAddress({addressType:addressType, networkName:networkName, wif:wif}).address
        let changeAddressType = getAddressType({address:changeAddress, networkName:networkName})
        outPutFeeDetails.set(changeAddressType, 1)
      }
      
      if(outPutFeeDetails.get(receiverAddressType) === 0|undefined){
        outPutFeeDetails.set(receiverAddressType, 1)
      }else{
        outPutFeeDetails.set(receiverAddressType, outPutFeeDetails.get(receiverAddressType)+1)
      }
      output.push({
        address:receiver,
        value:amount
      })
      
      outPutFeeDetails.forEach((value, key) => {
        outFeeData.push({
          outputType: key,
          count: value
        })
      })

      let utxos = await getAllUtxo({networkName:networkName, address:account.address})
    
      let spendableUtxos = utxos.map(x => {
        ids.push(x.txid)
        if(x.isInscription === false)
        return x
      })
      
      for(let i = 0; i < spendableUtxos.length; i++){
        let inputCount = 0
        if(input.length > 0){
          inputCount = input.length
        }
        availableInput = availableInput + spendableUtxos[i].value
        let txSize = getTransactionSize({input: inputCount, output:outFeeData, addressType: addressType})
        let txFee = txSize.txBytes * feeRate
        if(availableInput - txFee - amount < 550){
          input.push({
            txid: spendableUtxos[i].txid,
            vout: spendableUtxos[i].vout,
            value: spendableUtxos[i].value
          })
          continue;
        }else{
          input.push({
            txid: spendableUtxos[i].txid,
            vout: spendableUtxos[i].vout,
            value: spendableUtxos[i].value
          })
          break;
        }
      }

      let txSize = getTransactionSize({input: input.length, output:outFeeData, addressType: addressType})
      let txFee = txSize.txBytes * feeRate
      if(availableInput < txFee + amount + 550) throw new Error("available balance is not sufficient for transaction")
      let transactionDetails;

      if(privateKey){
          transactionDetails = await createTransaction({
          input:input, 
          output:output, 
          addressType:addressType, 
          networkName:networkName,
          feeRate:feeRate,
          privateKey
        })
      }else if(wif){
        transactionDetails = await createTransaction({
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

  export function signTransaction ({networkName, privateKey,wif, addressType, input, output}){
    try{
      const network = getNetwork(networkName)
      let keyPair;
      if(privateKey){
        keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey), {network})
      }else if(wif){
        keyPair = ECPair.fromWIF(transaction.wif, network)
      }
      if(addressType === "taproot"){
        keyPair = tweakSigner(keyPair, network)
      }
      let psbt = new Psbt({network})
      .addInputs(input)
      .addOutputs(output)
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
 export async function getInputData(addressType, input, networkName, privateKey, wif){
    try{
      let{transactions} = await init(networkName)
      let network = getNetwork(networkName)
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
          let tweakedSigner = tweakSigner(keyPair, { network });
          inData = inputTx.map((x) =>{
            return {
              hash:x.tx.txid,
              index:x.vout,
              witnessUtxo: {value: x.tx.vout[x.vout].value, script: Buffer.from(x.tx.vout[x.vout].scriptpubkey, "hex")},
              tapInternalKey: toXOnly(tweakedSigner.publicKey)
            }
          })
          break
      }
      return inData
    }catch(e){

    }
  }

  //output = [{outputType: "P2TR", count: 2}, {outputType: "P2PKH", count: 2}]
 export function getTransactionSize ({input, output, addressType}){
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

      let txVBytes = getTxOverheadVBytes(inputScript, input, output.length) +
                    inputSize * input +
                    P2PKH_OUT_SIZE * p2pkh_output_count +
                    P2WPKH_OUT_SIZE * p2wpkh_output_count +
                    P2TR_OUT_SIZE * p2tr_output_count + 
                    P2SH_OUT_SIZE * p2sh_output_count;
        txVBytes = Math.ceil(txVBytes);

        var txBytes = Math.ceil(getTxOverheadExtraRawBytes(inputScript, input) + txVBytes + (inputWitness * input) * 3 / 4);
        var txWeight = Math.ceil(txVBytes * 4);

        return {txVBytes:txVBytes, txBytes:txBytes, txWeight:txWeight}
    }catch(e){
      throw new Error(e.message)
    }
}

  function getNetwork (networkName) {
    if (networkName === "mainnet") {
      return networks.bitcoin;
    } else if (networkName === "testnet") {
      return networks.testnet;
    }
  };

  //Address validation helpers
  function mainnetAddressType (address, networkName) {
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

        if(checkTaproot(trimmedAddress, networkName) == true ){
          return "P2TR"
        }

        if(checkSegwit(trimmedAddress, networkName) == true){
          return "P2WPKH"
        }

        return null;
    }catch(e){
      throw new Error(e.message)
    }
  }

  function testnetAddressType (address) {
    try{
        const trimmedAddress = address.trim();

        if (/^m[0-9A-Za-z]{25,34}$/.test(trimmedAddress)) {
          return 'P2PKH';
        }
    
        if (/^2[0-9A-Za-z]{25,34}$/.test(trimmedAddress)) {
          return 'P2SH';
        }

        if (trimmedAddress.startsWith('tb1q')) {
          return 'P2WPKH';
        }
        if (trimmedAddress.startsWith('tb1p')) {
          return 'P2TR';
        }
        
        return null;
    }catch(e){
      throw new Error(e.message)
    }
  }


  function checkTaproot (address, networkName)  {
    try {
      if(networkName === "mainnet" && address.startsWith("tb1q")) return false
      if(networkName === "mainnet" && address.startsWith("tb1p")) return false
      let isTaproot = bech32m.decode(address).words;
      if(isTaproot[0] === 0x1) return true
    } catch (error) {
      return false;
    }
  }

  function checkSegwit (address, networkName)  {
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
  function tweakSigner(signer, opts) {
    let privateKey = signer.privateKey;
    if (!privateKey) {
      throw new Error("Private key is required for tweaking signer!");
    }
    if (signer.publicKey[0] === 3) {
      privateKey = tinysecp.privateNegate(privateKey);
    }
  
    const tweakedPrivateKey = tinysecp.privateAdd(
      privateKey,
      tapTweakHash(toXOnly(signer.publicKey), opts.tweakHash)
    );
    if (!tweakedPrivateKey) {
      throw new Error("Invalid tweaked private key!");
    }
  
    return ECPair.fromPrivateKey(Buffer.from(tweakedPrivateKey), {
      network: opts.network,
    });
  }
  
  function tapTweakHash(pubKey, h) {
    return crypto.taggedHash(
      "TapTweak",
      Buffer.concat(h ? [pubKey, h] : [pubKey])
    );
  }
  
  function toXOnly(pubkey) {
    return pubkey.subarray(1, 33);
  }
  
  // Transaction Size Helpers
  
  function getSizeOfVarInt (length) {
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

  function getTxOverheadVBytes (input_script, input_count, output_count) {
    if (input_script == "P2PKH" || input_script == "P2SH") {
      var witness_vbytes = 0;
    } else { // Transactions with segwit inputs have extra overhead
      var witness_vbytes = 0.25                 // segwit marker
                        + 0.25                  // segwit flag
                        + input_count / 4;      // witness element count per input
    }

    return 4 // nVersion
          + getSizeOfVarInt(input_count) // number of inputs
          + getSizeOfVarInt(output_count) // number of outputs
          + 4 // nLockTime
          + witness_vbytes;
  }

  function getTxOverheadExtraRawBytes (input_script, input_count) {
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

  function hasPushDataOpcode(script) {
    const pushDataPattern = /OP_PUSHDATA[1-4]/;
    return pushDataPattern.test(script);
  }

  export async function getAllUtxo ({networkName, address}) {
    try{
      let utxos = await getUtxo({networkName:networkName, address:address})
      let allTx = await Promise.all(utxos.map(async (x) => {
        return {
          txid: x.txid,
          vout: x.vout,
          value: x.value,
          isInscription: await hasInscription({utxo:x, address:address, networkName:networkName})
        }
    }))
    return allTx;
    }catch(e){
      throw new Error(e.message)
    }
  }

  export async function hasInscription ({utxo, address, networkName}){
    try{
      let {transactions} = await init(networkName) 
      let addressType = getAddressType({address:address, networkName:networkName})
      if(addressType == "P2TR" || addressType == "P2WPKH") {
        let tx = await transactions.getTx({txid: utxo.txid})
        if(tx.vout[utxo.vout].scriptpubkey_address === address && tx.vin[0].inner_witnessscript_asm !== undefined|null){
          return hasPushDataOpcode(tx.vin[0].inner_witnessscript_asm)
        }else{
          return false
        }
      }else{
        return false
      } 
    }catch(e){
      throw new Error(e.message)
    }
  }

  export async function genQrCode (data){
    try{
      return await QRCode.toDataURL(data)
    }catch(e){
      throw new Error(e.message)
    }
  }

  //inscriptionUtxo
  export async function createInscriptionTransacrion ({inscriptionUtxo, receiver, feeRate, networkName, addressType, privateKey, wif}) {
    //get all utxos
    if(addressType === "legacy") throw new Error("Legacy address does not support inscriptions")
    let account
    let output = []
    let input = []
    let outPutFeeDetails = new Map();
    let outFeeData = []
    let availableInput = 0

    let receiverAddressType = getAddressType({address:receiver, networkName:networkName})
    if(privateKey){
      account = createAddress({networkName:networkName, privateKey:privateKey, addressType:addressType})
      let accountType = getAddressType({address:account.address, networkName:networkName})
      outPutFeeDetails.set(accountType, 1)
    }else{
      account = createAddress({networkName:networkName, wif:wif, addressType:addressType})
      let accountType = getAddressType({address:account.address, networkName:networkName})
      outPutFeeDetails.set(accountType, 1)
    }

    if(!outPutFeeDetails.has(receiverAddressType)){
      outPutFeeDetails.set(receiverAddressType, 1)
    }else{
      outPutFeeDetails.set(receiverAddressType, outPutFeeDetails.get(receiverAddressType)+1)
    }
    output.push({
      address: receiver,
      value: inscriptionUtxo.value
    })
    outPutFeeDetails.forEach((value, key) => {
      outFeeData.push({
        outputType: key,
        count: value
      })
    })
    
    let utxos = await getAllUtxo({networkName:networkName, address:account.address})
    let ids = []
    let spendableUtxos = utxos.map(x => {
      ids.push(x.txid)
      if(x.isInscription === false)
      return x
    })
    if(!ids.includes(inscriptionUtxo.txid)) throw new Error("inscription utxo not found")
    input.push(inscriptionUtxo)

    for(let i = 0; i < spendableUtxos.length; i++){
      if(input.length == 1){
        availableInput = availableInput + inscriptionUtxo.value
      }else if(input.length > 1){
        availableInput = availableInput + spendableUtxos[i].value
      }
      let txSize = getTransactionSize({input: input.length, output:outFeeData, addressType: addressType})
      let txFee = txSize.txBytes * feeRate
      if(availableInput - txFee < 550){
        input.push({
          txid: spendableUtxos[i].txid,
          vout: spendableUtxos[i].vout,
          value: spendableUtxos[i].value
        })
        continue;
      }else{
        input.push({
          txid: spendableUtxos[i].txid,
          vout: spendableUtxos[i].vout,
          value: spendableUtxos[i].value
        })
        break;
      }
    }
    
    let changeAmount = availableInput - inscriptionUtxo.txid - txFee
    
    if(inscriptionUtxo.txid + txFee > availableInput) {
      throw new Error("not enough utxo balance for transactions")
    }else if(changeAmount < 550 && changeAmount > 0){
      let inputData = await getInputData(addressType, input, networkName, privateKey, wif)
      let signedTx = signTransaction({networkName:networkName, privateKey:privateKey, wif:wif, addressType:addressType, input:inputData, output:output})
      return {
        txHex: signedTx.txHex,
        tx: signedTx.signedTransaction,
        fee: txFee,
        satSpent: inscriptionUtxo.txid + txFee ,
        txSize: txSize
      }
    }else{
      output.push({
        address: account.address,
        value: changeAmount
      })
      let inputData = await getInputData(addressType, input, networkName, privateKey, wif)
      let signedTx = signTransaction({networkName:networkName, privateKey:privateKey, wif:wif, addressType:addressType, input:inputData, output:output})
      return {
        txHex: signedTx.txHex,
        tx: signedTx.signedTransaction,
        fee: txFee,
        satSpent:inscriptionUtxo.txid + txFee ,
        txSize: txSize
      }
    }
  }

