import bitcore from "bitcore-lib";
import Mnemonic from "bitcore-mnemonic";
import {
    initEccLib,
    networks,
    crypto,
    payments,
    Psbt,
    script,
    Transaction
} from "bitcoinjs-lib";
import * as tinysecp from "tiny-secp256k1";
import  { ECPairFactory } from "ecpair";
import mempoolJS from "@mempool/mempool.js";
import {bech32m, bech32} from 'bech32';
import QRCode from 'qrcode'
import { Address } from '@cmdcode/tapscript'
import axios from "axios";



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
    let xpriv = code.toHDPrivateKey(passPhrase).derive(`m/86/0/${path}`);
    let privateKey = xpriv.privateKey.toString();
    let keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey, "hex"), {network});
    
    return {
      privateKey: keyPair.privateKey.toString(),
      raw_privateKey: keyPair,
      wif: keyPair.toWIF(),
      pubKey: keyPair.publicKey
    };
  }catch(e){
    throw new Error(e)
  }
};

  export function createAddress ({privateKey, wif, networkName, addressType}) {
    try {
      const network = getNetwork(networkName);
      let keyPair;
      if(privateKey){
        //make the private key 32 bytes
        keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey, "hex"), {network})
      }else if(wif){
        keyPair = ECPair.fromWIF(wif, network)
      }
      let address;
      let script;
      let publicKey;

      switch (addressType){
        case "taproot":
          const tweakedSigner = tweakSigner(keyPair, { network });
          const p2tr = payments.p2tr({
          pubkey: toXOnly(tweakedSigner.publicKey),
          network,
        });
        address = p2tr.address ?? "";
        script = p2tr.output;
        publicKey = p2tr.pubkey
        break;
        case "legacy":
          const p2pkh = payments.p2pkh({ pubkey: keyPair.publicKey, network: network })
          address = p2pkh.address ?? "";
          script = p2pkh.output;
          publicKey = p2pkh.pubkey
        break;
        case "segwit":
          const p2wpkh = payments.p2wpkh({ pubkey: keyPair.publicKey , network: network})
          address = p2wpkh.address ?? "";
          script = p2wpkh.output;
          publicKey = p2wpkh.pubkey
          break
      }
      return { address: address, script: script, publicKey: publicKey};
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
        }else if(wif){
          addressDetails = createAddress({wif: wif, networkName:networkName, addressType:x})
        }
        return {
          address: addressDetails.address,
          addressType: x,
          scriptType: getAddressType({address:addressDetails.address, networkName:networkName}),
          script: addressDetails.script,
          publicKey: addressDetails.publicKey.toString("hex")
        }
      })

      return addressList;
    }catch(e){
      throw new Error(e.message)
    }
  }


  export async function init (network) {
    if(network === "fractal_testnet"){
      const {
        bitcoin: { addresses, fees, transactions },
      } = mempoolJS({
        hostname: "mempool-testnet.fractalbitcoin.io",
      });
      return { addresses, fees, transactions };
    }

    if(network === "fractal_mainnet"){
      const {
        bitcoin: { addresses, fees, transactions },
      } = mempoolJS({
        hostname: "mempool.fractalbitcoin.io",
      });
      return { addresses, fees, transactions };
    }

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
        case "fractal_mainnet":
          addressType = mainnetAddressType(address, "mainnet")
          break
        case "fractal_testnet":
          addressType = mainnetAddressType(address, "mainnet")
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

  export async function getUtxo({address ,networkName})  {
    try{
      if(!address) return {status: false, data: null, message: "address is required"}
      if(networkName === 'fractal_mainnet' || networkName === 'fractal_testnet'){
        const {addresses} = await init(networkName)
        const utxos = await addresses.getAddressTxsUtxo({address: address})
        if(utxos.length === 0) return []
        return utxos
      }
      
      const url = networkName === "mainnet" ? `https://blockstream.info/api/address/${address}/utxo` : networkName === "testnet" ? `https://blockstream.info/testnet/api/address/${address}/utxo` : null
      if(url === null) return {status: false, data: null, message: "invalid network"}
      const response = await axios.get(url)
      //const response = {status: 400, data: {}}
      if(response.status !== 200) {
        const {addresses} = await init(networkName)
        const utxos = await addresses.getAddressTxsUtxo({address: address})
        if(utxos.length === 0) return []
        return utxos 
      }
      return response.data
    }catch(e){
      console.log(e)
      throw new Error(e.message)
    }
  }

  export async function n_getUtxo ({networkName, address}){
    try{
      if(address === undefined) throw new Error("address is required")
      if(networkName === undefined) throw new Error("network name is required")
      if(networkName !== "mainnet" && networkName !== "testnet") throw new Error("invalid network name")
      if(networkName === "mainnet"){
        return await _getUtxo({address:address})
      }
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

  const _getUtxo = async ({address}) => {
    try{
      const result = await axios.get(`https://blockchain.info/unspent?active=${address}`);
      let n_utxo = result.data.unspent_outputs
      n_utxo = n_utxo.map(x => {
        
        return {
          txid: x.tx_hash_big_endian,
          vout: x.tx_output_n,
          status: {
            confirmed: x.confirmations >= 1 ? true : false
          },
          value: x.value
        }
      })
      return n_utxo;
      
    }catch(e){
      console.log(e);
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
  export async function createTransaction ({input, output, addressType, networkName, feeRate, privateKey, wif, changeAddress}) {
    try{ 
      let outputData = output
      let totalAvailable = 0;
      let toSpend = 0;
      let outPutFeeDetails = new Map();
      let outFeeData = [];

      let _publicKey;
      let _script
      if(privateKey){
        let {publicKey, script} = createAddress({privateKey: privateKey, networkName: networkName, addressType: addressType})
        _publicKey = publicKey;
        _script = script
      }else if(wif){
        let {publicKey, script} = createAddress({wif: wif, networkName: networkName, addressType: addressType})
        _publicKey = publicKey;
        _script = script
      }

      if(changeAddress || changeAddress !== undefined){
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

      // outPutFeeDetails = mapping
      // outFeeData = array
      outPutFeeDetails.forEach((value, key) => {
        outFeeData.push({
          outputType: key,
          count: value
        })
      })

      let txSize = getTransactionSize({input: input.length, output:outFeeData, addressType: addressType})
      let txFee = txSize.txVBytes * feeRate
      let changeAmount = totalAvailable - txFee - toSpend
      
      if(toSpend + txFee > totalAvailable) {
        throw new Error("not enough utxo balance for transactions")
      }

  
      if(changeAddress && changeAmount > 1000){
        outputData.push({address:changeAddress, value: totalAvailable - toSpend - txFee})
      }
      const inputData = await getInputData(addressType, input, networkName, _publicKey, _script)
      const signedTx = signTransaction({networkName:networkName, privateKey:privateKey, wif:wif, addressType:addressType, input:inputData, output:outputData})
      return {
        txHex: signedTx.txHex,
        tx: signedTx.signedTransaction,
        fee: txFee,
        satSpent: toSpend + txFee,
        txSize: txSize
      }
    
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
        keyPair = ECPair.fromWIF(wif, network)
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
  
  export function getPsbtDetails ({networkName, input, output}){
    try{
      let psbt = new Psbt({network: getNetwork(networkName)})
      .addInputs(input)
      .addOutputs(output)
      return {psbtHex: psbt.data.toHex(), psbtBase64: psbt.data.toBase64()};
    }catch(e){
      throw new Error(e.message)
    }
  }

  export async function createTransaction2 ({input, output, addressType, networkName, feeRate, changeAddress, publicKey, script}) {
    try{ 
      let outputData = output
      let totalAvailable = 0;
      let toSpend = 0;
      let outPutFeeDetails = new Map();
      let outFeeData = [];

      let pubKey = hexToBuffer(publicKey);
      
      if(changeAddress || changeAddress !== undefined){
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

      // outPutFeeDetails = mapping
      // outFeeData = array
      outPutFeeDetails.forEach((value, key) => {
        outFeeData.push({
          outputType: key,
          count: value
        })
      })

      let txSize = getTransactionSize({input: input.length, output:outFeeData, addressType: addressType})
      let txFee = txSize.txVBytes * feeRate
      let changeAmount = totalAvailable - txFee - toSpend
      
      if(toSpend + txFee > totalAvailable) {
        throw new Error("not enough utxo balance for transactions")
      }
  
      if(changeAddress && changeAmount > 1000){
        outputData.push({address:changeAddress, value: totalAvailable - toSpend - txFee})
      }
      const inputData = await getInputData(addressType, input, networkName, pubKey, script)
      let psbtData = getPsbtDetails({networkName:networkName, input:inputData, output:outputData})
      return {
        psbt: {
          psbtHex: psbtData.psbtHex,
          psbtBase64: psbtData.psbtBase64,
        },
        fee: txFee,
        satSpent: toSpend + txFee,
        txSize: txSize
      }
    
    }catch(e){
      console.log(e.message)
      throw new Error(e.message)
    }
  }

  export async function addInputToPsbt ({psbt, networkName, addressType, input, publicKey, script}) {
    try{
      const network = getNetwork(networkName)
      let pubKey = hexToBuffer(publicKey);
      if(psbt.psbtHex){
        let psbtData = Psbt.fromHex(psbt.psbtHex, {network})
        let inputData = await getInputData(addressType, input, networkName, pubKey, script)
        psbtData.addInputs(inputData)
        return {psbtHex: psbtData.toHex(), psbtBase64: psbtData.toBase64()}
      }
      if(psbt.psbtBase64){
        let psbtData = Psbt.fromBase64(psbt.psbtBase64, {network})
        let inputData = await getInputData(addressType, input, networkName, pubKey, script)
        psbtData.addInputs(inputData)
        return {psbtHex: psbtData.toHex(), psbtBase64: psbtData.toBase64()}
      }
    }catch(e){
      console.log(e)
      throw new Error(e.message)
    }
  }

  export function signTransaction2 ({psbt, networkName, privateKey, wif, addressType, index}) {
    try{
      const network = getNetwork(networkName)
      let keyPair;
      let publicKey;
      if(privateKey){
        keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey, "hex"), {network})
        publicKey = createAddress({privateKey: privateKey, networkName: networkName, addressType: addressType}).publicKey
      }else if(wif){
        keyPair = ECPair.fromWIF(wif, network)
        publicKey = createAddress({wif: wif, networkName: networkName, addressType: addressType}).publicKey
      }
      if(addressType === "taproot"){
        keyPair = tweakSigner(keyPair, network)
      }
      
      let psbtData 
      if(psbt.psbtBase64){
        psbtData = Psbt.fromBase64(psbt.psbtBase64, {network})
      }else if(psbt.psbtHex){
        psbtData = Psbt.fromHex(psbt.psbtHex, {network})
      }

      psbtData.signInput(index, keyPair)
      psbtData.finalizeInput(index)

      return {psbtHex: psbtData.toHex(), psbtBase64: psbtData.toBase64()}
    }catch(e){
      console.log(e)
      throw new Error(e.message)  
    }
  }
  
   //input = [{txid: "", vout: 2, value: 20000}, {txid: "", vout: 0, value: 20000}]
 export async function getInputData(addressType, input, networkName, publicKey, script){
  try{
    let{transactions} = await init(networkName)
    let inData;
    let url
    // if(networkName === "mainnet"){
    //   url = "https://blockstream.info/api/tx/"
    // }
    // if(networkName === "testnet"){
    //   url = "https://blockstream.info/testnet/api/tx/"
    // }

    // let _inputTx = await Promise.all(input.map(async(item, index)=>{
    //   let tx = await axios.get(`${url}/${item.txid}`)
    //   tx = tx.data
    //   return {tx: tx, vout: item.vout}
    // }))
    
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
        inData = input.map((x) =>{
          return {
            hash:x.txid,
            index:x.vout,
            witnessUtxo: {value: x.value, script: script},
          }
        })
        break
      case "taproot":
        inData = input.map((x) =>{
          return {
            hash:x.txid,
            index:x.vout,
            witnessUtxo: {value: x.value, script: script},
            tapInternalKey: publicKey
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
    if (networkName === "mainnet" || networkName === "fractal_mainnet" || networkName === "fractal_testnet"  ) {
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
    try{
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
    }catch(e){
      throw new Error(e.message)
    }
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

  function buf2hex(buffer) { // buffer is an ArrayBuffer
    return [...new Uint8Array(buffer)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
  }

  function hexToBuffer(hex) {
    return Buffer.from(hex, 'hex');
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
      let txFee = txSize.txVBytes * feeRate
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
    let inputData
    
    if(inscriptionUtxo.txid + txFee > availableInput) {
      throw new Error("not enough utxo balance for transactions")
    }else if(changeAmount < 550 && changeAmount > 0){
      inputData = await getInputData(addressType, input, networkName, privateKey, wif, account.script)
    }else{
      output.push({
        address: account.address,
        value: changeAmount
      })
      inputData = await getInputData(addressType, input, networkName, privateKey, wif, account.script)
    }

    let signedTx = signTransaction({networkName:networkName, privateKey:privateKey, wif:wif, addressType:addressType, input:inputData, output:output})
    return {
      txHex: signedTx.txHex,
      tx: signedTx.signedTransaction,
      fee: txFee,
      satSpent:inscriptionUtxo.txid + txFee ,
      txSize: txSize
    }
  }


  //getUtxo({address: "bc1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0yskfd9lc", networkName: "fractal_testnet"}).then(res => console.log(res)).catch()