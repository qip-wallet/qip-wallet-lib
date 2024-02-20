import crypto from "crypto"
import FileReader from 'filereader'
import mimeTypes from 'mime-types'
   import cbor from 'cbor'
import path from 'path'
import atob from "atob"
import fs from "fs"
import buf from "buffer"
import { Address, Script, Signer, Tap, Tx } from '@cmdcode/tapscript'
import {cryptoUtils} from "../bitcoin/lib/cryptoUtils.js"
import axios from 'axios'
import {
   networks,
   Psbt,
} from "bitcoinjs-lib";
import {
   init, 
   getTransactionSize, 
   getUtxo, 
   getAllAddress, 
   signTransaction2, 
   getPsbtDetails, 
   getInputData
} from './utils.js'

const getFileData = async (file) => {
   try{    
       let files = [];
       for (let i = 0; i < file.length; i++) {
           let filename = file[i].split("/")[file[i].split("/").length -1]
           let filePath = file[i]
           let fileSize = fs.readFileSync(filePath).length
           let mimetype = getMimeType(path.extname(file[i]));

           let _file = {name: filename, path: filePath, size:fileSize, type:mimetype }

           if (file[i].size >= 350000) {
               throw new Error ("file size exceeds limit: ", file[i])
           } 

           let b64;

           if (mimetype.includes("text/plain")) {
               mimetype += ";charset=utf-8";
               const text =  fs.readFileSync(filePath).toString()
               files.push({
                   name: _file.name,
                   hex: textToHex(text),
                   mimetype: mimetype,
                   sha256: ""
               });
           }else{
               b64 = await encodeBase64(_file);
               let base64 = b64.substring(b64.indexOf("base64,") + 7);
               let hex = base64ToHex(base64);
               let sha256 = await fileToSha256Hex({name: _file.name, path:_file.path});
               files.push({
                   name: _file.name,
                   hex: hex,
                   mimetype: mimetype,
                   sha256: sha256.replace('0x', '')
               });
           }
       
       }
       return files
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
};

export const covertJsonToCbor = (obj) => {
   let n_cbor = cbor.encode(obj)
   return n_cbor
}

export const getAddressEncoding = ({networkName}) => {
   if(networkName === "mainnet"){
       return "main"
   }else if(networkName === "testnet"){
       return "testnet"
   }else{
       throw new Error (`networkName can only be mainnet, or testnet, received: ${networkName}`)
   }
}

export const getKeyPair = ({privateKey}) => {
   try{
       let privkey
       if(!privateKey){
           privkey = bytesToHex(cryptoUtils.Noble.utils.randomPrivateKey());
       }else{
           privkey = privateKey
       }

       const KeyPair = cryptoUtils.KeyPair;

       let seckey = new KeyPair(privkey);
       let pubkey = seckey.pub.rawX;

       return {
           seckey: seckey, pubkey: buf2hex(pubkey.buffer), privkey: privkey
       }

   }catch(e){
       throw new Error(e.message)
   }
}

const createInscriptionScript = ({pubkey, mimetype, data, metadata}) => {
   try{
       const ec = new TextEncoder();
       if(!pubkey || !mimetype || !data){
           throw new Error ("pubkey, mimetype, and data are required to create an inscription script. Received: ", pubkey, mimetype, data)
       }
       
       let script = [];
       let script_backup = [];
       if(!metadata){
           script = [ 
               pubkey,
               'OP_CHECKSIG',
               'OP_0',
               'OP_IF',
               ec.encode('ord'),
               '01',
               mimetype,
               'OP_0',
               data,
               'OP_ENDIF'
           ];

           script_backup = [
               '0x' + buf2hex(pubkey.buffer),
               'OP_CHECKSIG',
               'OP_0',
               'OP_IF',
               '0x' + buf2hex(ec.encode('ord')),
               '01',
               '0x' + buf2hex(mimetype),
               'OP_0',
               '0x' + buf2hex(data),
               'OP_ENDIF'
           ];

           return {
               script: script,
               script_backup: script_backup
           }
       }

       script = [
           pubkey,
           'OP_CHECKSIG',
           'OP_0',
           'OP_IF',
           ec.encode('ord'),
           '01',
           mimetype,
           '05',
           Uint8Array.from(covertJsonToCbor(metadata)), //CBOR
           'OP_0',
           data,
           'OP_ENDIF'
       ];

       script_backup = [
           '0x' + buf2hex(pubkey.buffer),
           'OP_CHECKSIG',
           'OP_0',
           'OP_IF',
           '0x' + buf2hex(ec.encode('ord')),
           '01',
           '0x' + buf2hex(mimetype),
           '05',
           '0x' + buf2hex(Uint8Array.from(covertJsonToCbor(metadata))), //CBOR
           'OP_0',
           '0x' + buf2hex(data),
           'OP_ENDIF'
       ];

       return {
           script: script,
           script_backup: script_backup
       }
   }catch(e){
       throw new Error(e.message)
   }
}

const createBatchInscriptionScript = ({pubkey, inscriptionData}) => {
   try{
       const ec = new TextEncoder();
       if(!pubkey || !inscriptionData){
           throw new Error ("pubkey, mimetype, and inscriptionData are required to create an inscription script. Received: ", pubkey, inscriptionData)
       }
       
       let script = [];
       let script_backup = [];
       
       let spriptHeader = [pubkey, 'OP_CHECKSIG']
       let scriptBackupHeader = ['0x' + buf2hex(pubkey.buffer), 'OP_CHECKSIG']
       
       inscriptionData.map(x => {
           const data = hexToBytes(x.fileData.hex)
           const mimetype = ec.encode(x.fileData.mimetype);
           if(!x.metadata){
               script.push('OP_0', 'OP_IF', ec.encode('ord'), '01', mimetype, 'OP_0', data, 'OP_ENDIF')
               script_backup.push('OP_0', 'OP_IF', '0x' + buf2hex(ec.encode('ord')), '01', '0x' + buf2hex(mimetype), 'OP_0', '0x' + buf2hex(data), 'OP_ENDIF')
           }else{
               script.push('OP_0', 'OP_IF', ec.encode('ord'), '01', mimetype, '05', Uint8Array.from(covertJsonToCbor(x.metadata)), 'OP_0', data, 'OP_ENDIF')
               script_backup.push('OP_0', 'OP_IF', '0x' + buf2hex(ec.encode('ord')), '01', '0x' + buf2hex(mimetype), '05', '0x' + buf2hex(Uint8Array.from(covertJsonToCbor(x.metadata))), 'OP_0', '0x' + buf2hex(data), 'OP_ENDIF')
           }
       })
       // add the header to the script
       script = spriptHeader.concat(script)
       script_backup = scriptBackupHeader.concat(script_backup)

       return { script: script, script_backup: script_backup }

   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
}

const getInitData = ({privateKey, networkName}) => {
  try {
       if(!networkName){
           throw new Error (`networkName can only be mainnet, or testnet, received: ${networkName}`)
       }

       let addressEncoding = getAddressEncoding({networkName: networkName})
       let privkey;
       if(!privateKey){
           privkey = bytesToHex(cryptoUtils.Noble.utils.randomPrivateKey());
       }else{
           privkey = privateKey
       }
       
       const KeyPair = cryptoUtils.KeyPair;
       let seckey = new KeyPair(privkey);
       let pubkey = seckey.pub.rawX;

       const init_script = [
           pubkey,
           'OP_CHECKSIG'
       ];

       const init_script_backup = [
           '0x' + buf2hex(pubkey.buffer),
           'OP_CHECKSIG'
       ];

       let init_leaf = Tap.encodeScript(init_script);
       let [init_tapkey, init_cblock] = Tap.getPubKey(pubkey, {target: init_leaf});

       /**
        * This is to test IF the tx COULD fail.
        * This is most likely happening due to an incompatible key being generated.
        */
       const test_redeemtx = Tx.create({
           vin  : [{
               txid: 'a99d1112bcb35845fd44e703ef2c611f0360dd2bb28927625dbc13eab58cd968',
               vout: 0,
               prevout: {
                   value: 10000,
                   scriptPubKey: [ 'OP_1', init_tapkey ]
               },
           }],
           vout : [{
               value: 8000,
               scriptPubKey: [ 'OP_1', init_tapkey ]
           }],
       });

       const test_sig = Signer.taproot.sign(seckey.raw, test_redeemtx, 0, {extension: init_leaf});
       test_redeemtx.vin[0].witness = [ test_sig.hex, init_script, init_cblock ];
       const isValid = Signer.taproot.verify(test_redeemtx, 0, { pubkey });

       if(!isValid)
       {
           throw new Error ('Generated keys could not be validated, Try again');
       }

       let fundingAddress = Address.p2tr.encode(init_tapkey, addressEncoding);
   
       return {
           privateKey: privkey,
           publicKey: buf2hex(pubkey.buffer),
           validSigner: true,
           fundingAddress: fundingAddress,
           // scripts: {
           //     init_script: init_script,
           //     init_script_backup: init_script_backup
           // },
           init_leaf:init_leaf,
           init_cblock: init_cblock,
           init_tapkey: init_tapkey,
           version: "v1"
       }
   }catch(e){
       throw new Error(e.message)
   }
}

export const getInitData2 = ({privateKey, networkName}) => {
   try {
        if(!networkName){
            throw new Error (`networkName can only be mainnet, or testnet, received: ${networkName}`)
        }

        let privkey;
        if(!privateKey){
            privkey = bytesToHex(cryptoUtils.Noble.utils.randomPrivateKey());
        }else{
            privkey = privateKey
        }
        
        const data = getAllAddress({networkName: networkName, privateKey: privkey})
    
        return {
            privateKey: privkey,
            publicKey: getInitData({privateKey: privkey, networkName: networkName}).publicKey,
            tap_publicKey: data[0].addressType === "taproot" ? data[0].publicKey : null,
            validSigner: true,
            fundingAddress: data[0].addressType === "taproot" ? data[0].address : null,
            version: "v2"
        }
    }catch(e){
        throw new Error(e.message)
    }
}

const _getInscription = ({files, publicKey, networkName, feerate, padding, options}) => {
   try{
       const ec = new TextEncoder();
       if(!files) throw new Error ("files is required")
       if(!feerate) throw new Error ("feerate is required")
       if(!publicKey) throw new Error ("publicKey is required")
       if(!networkName) throw new Error ("networkName is required")
       const hex = files.hex;
       const data = hexToBytes(hex);
       const mimetype = ec.encode(files.mimetype);
       
       let pubkey = hexToBytes(publicKey);
       let addressEncoding = getAddressEncoding({networkName: networkName})
       
       let pad
       if(!padding || padding < 550){
           pad = 550
       }else{
           pad = padding
       }

       let script = [];
       let script_backup = [];

       let extra_bytes = 0;
       if(options && options.metadata){
           const scriptData = createInscriptionScript({pubkey: pubkey, mimetype: mimetype, data: data, metadata: options.metadata})
           script = scriptData.script;
           script_backup = scriptData.script_backup;
           extra_bytes = 80
       }else{
           const scriptData = createInscriptionScript({pubkey: pubkey, mimetype: mimetype, data: data})
           script = scriptData.script;
           script_backup = scriptData.script_backup;
       }

       const leaf = Tap.encodeScript(script);
       const [tapkey, cblock] = Tap.getPubKey(pubkey, { target: leaf });

       const inscriptionAddress = Address.p2tr.encode(tapkey, addressEncoding);        
       const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;

       const _extra_bytes = extra_bytes * feerate
       
       const txsize = _extra_bytes + Math.ceil(data.length / 4) * feerate;
       const fee = txsize + pad + prefix;
       
       return {
           leaf: leaf,
           tapkey: tapkey,
           cblock: cblock,
           inscriptionAddress: inscriptionAddress,
           txsize: txsize,
           fee: fee,
           script: script_backup,
           script_orig: script,
           padding: pad
       }
       
   }catch(e){
       throw new Error(e.message)
   }
}

const getBatchInscription = async ({publicKey, networkName, feerate, padding, options}) => {
   try{
       const ec = new TextEncoder();
       if(!publicKey) throw new Error("publicKey is required")
       if(!networkName) throw new Error("networkName is required")
       if(!options || !options.batch) throw new Error ("batch data is required")
       if(!options.batch.data || options.batch.data.length === 0) throw new Error ("batch data is required")
       if(!feerate) throw new Error ("feerate is required")
       let pubkey = hexToBytes(publicKey);
       let addressEncoding = getAddressEncoding({networkName: networkName})

       let pad
       if(!padding || padding < 550){
           pad = 550
       }else{
           pad = padding
       }

       let extra_bytes = 0

       const files = options.batch.data.map(x => x.file)
       let _file = await getFileData(files)
       let incs_file_data = _file.map((x, i) => {
           if(options.batch.data[i].metadata) extra_bytes += 80
           return {
               fileData: x,
               metadata: options.batch.data[i].metadata,
               size: hexToBytes(x.hex).length,
           }
           
       })

       const {script, script_backup} = createBatchInscriptionScript({pubkey: pubkey, inscriptionData: incs_file_data})
       const leaf = Tap.encodeScript(script);
       const [tapkey, cblock] = Tap.getPubKey(pubkey, { target: leaf });
       const inscriptionAddress = Address.p2tr.encode(tapkey, addressEncoding);
       
       let inputCount = 1
       let prefix = getTransactionSize({input:inputCount, output:[{outputType: "P2TR", count:options.batch.data.length}], addressType: "taptoot"}).txVBytes * feerate;
       let totalSize = 0
       let _padding = 0
       
       incs_file_data.map(x => {
           totalSize += x.size
           _padding += pad
       })
       
       const _extra_bytes = extra_bytes * feerate
       let txsize = _extra_bytes + Math.ceil(totalSize/4) * feerate

       const fee = prefix + txsize + _padding;

       
       return {
           leaf: leaf,
           tapkey: tapkey,
           cblock: cblock,
           inscriptionAddress: inscriptionAddress,
           txsize: txsize,
           fee: fee,
           script: script_backup,
           script_orig: script,
           padding: pad,
       }
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }

}

export const getInscriptionCost = ({fileSizes, feerate, padding, options}) => {
   try{
       if(fileSizes && options.batch)throw new Error("fileSizes or batch data is required")
       if(!fileSizes && !options.batch)throw new Error("fileSizes or batch data is required")
       if(!feerate) throw new Error ("feerate is required")

       let pad
       if(!padding || padding < 550){
           pad = 550
       }else{
           pad = padding
       }

       let inputs = 1
       let outputCount = 0 
       let total_fees = 0

       let fileCount = 0
       if(fileSizes){
           fileCount = fileSizes.length
       }else{
           fileCount = options.batch.data.length
       }
       if(fileCount === 0) throw new Error ("fileSizes or batch data is required")

       if(options && options.sat_details) {
           if(fileCount > 1 && !options.batch) throw new Error ("special sat can only be used on one file")
           inputs += 1
           outputCount += 1
       }

       if(options && options.service_fee){
           if(!options.service_address) throw new Error ("service_address is required to add a service fee")
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += (options.service_fee) + prefix
           outputCount += 1
       }

       if(options && options.collection_fee){
           if(!options.collection_address) throw new Error ("collection_address is required to add a collection fee")
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += (options.collection_fee) + prefix
           outputCount += 1
       }

       let extra_bytes = 0
       if(options && options.batch){
           if(options.batch.parent) inputs += 1, outputCount += 1
           let totalSize = 0
           let _padding = 0
           options.batch.data.map(x => {
               if(x.metadata) extra_bytes += 80
               totalSize += x.size
               _padding += pad
           })
           const _extra_bytes = extra_bytes * feerate
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: fileCount}], addressType: "taptoot"}).txVBytes * feerate;
           const txsize = _extra_bytes + Math.ceil(totalSize / 4) * feerate;
           const fee = txsize + prefix + _padding;
           total_fees += fee;
           outputCount += fileCount
       }else{
           for (let i = 0; i < fileSizes.length; i++) {
               const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
               let txsize
               if(options && options.metadata) {
                   const _extra_bytes = 80 * feerate
                   txsize =  _extra_bytes + Math.ceil(fileSizes[i] / 4) * feerate;
               }else{
                   txsize = Math.ceil(fileSizes[i] / 4) * feerate;
               }
               const fee =  txsize + prefix + pad;
               total_fees += fee;
               outputCount += 1
           }  
       }

       let outFeeData = [{outputType: "P2TR", count: outputCount}]
       total_fees += getTransactionSize({input: inputs, output:outFeeData, addressType: "taptoot"}).txVBytes * feerate;
       return total_fees

   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
}

export const getInscriptions = async ({filePaths, publicKey, networkName, feerate, padding, options}) => {
   try{ 
       
       if(filePaths && options.batch)throw new Error("filePaths or batch data is required")
       if(!filePaths && !options.batch)throw new Error("filePaths or batch data is required")
   
       if(!publicKey) throw new Error("publicKey is required")
       if(!networkName) throw new Error("networkName is required")
       if(!feerate) throw new Error("feerate is required")

       let inscriptions = [];
       let inputs = 1
       let outputCount = 0
       let total_fees = 0

       if(options && options.sat_details){
           if(typeof options.sat_details.privateKey !== "string") throw new Error ("sat_privateKey must be a string")
           inputs += 1
           outputCount += 1
       }

       if(options && options.batch){
           if(!options.batch.data || options.batch.data.length === 0)  throw new Error("batch data is required")
           if(options.batch.parent) inputs += 1
           let inscData = await getBatchInscription({publicKey: publicKey, networkName: networkName, feerate: feerate, padding: padding, options: options})
           inscriptions.push(inscData)
           total_fees += inscData.fee
           outputCount += options.batch.data.length
       }else{
           let files = await getFileData(filePaths)
           if(files.length > 1 && options.sat_details) throw new Error (`inscription on special sat can only be done on one file, you have ${files.length} files`)
           for (let i = 0; i < files.length; i++) {
               let inscription = _getInscription({files: files[i], publicKey: publicKey, networkName: networkName, feerate: feerate, padding: padding, options: options})
               inscriptions.push(inscription)
               total_fees += inscription.fee
               outputCount += 1
           }
       }
       
       if(options && options.service_fee){
           if(!options.service_address) throw new Error ("service_address is required to add a service fee")
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += options.service_fee + prefix
           outputCount += 1
       }
       if(options && options.collection_fee){
           if(!options.collection_address) throw new Error ("collection_address is required to add a collection fee")
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += options.collection_fee + prefix
           outputCount += 1
       }
       
       let outFeeData = [{outputType: "P2TR", count: outputCount}]
       let totalSize = getTransactionSize({input: inputs, output:outFeeData, addressType: "taptoot"}).txVBytes*feerate
       total_fees += totalSize

       if(options && options.show_insc === false){
           let n_insc = inscriptions.map(x => {
               return {
                   inscriptionAddress: x.inscriptionAddress,
                   fee: x.fee,
                   padding: x.padding,
                   leaf: x.leaf,
                   tapkey: x.tapkey,
                   cblock: x.cblock,
                   txsize: x.txsize,
               }
           })
           return {
               inscriptions: n_insc,
               total_fees: total_fees
           }
       }
       return {
           inscriptions: inscriptions,
           total_fees: total_fees
       }
   }catch(e){
       console.log(e)
       throw new Error(e)
   }
}

const handleSatTx = async ({satTx, networkName, address}) => {
   try{
       if(!satTx.vout && !satTx.txid){
           throw new Error ("satTx txid, vout and required")
       }
       if(typeof satTx.txid !== "string"){
           throw new Error ("satTx Txid must be a string")
       }
       let utxos = await getUtxo({networkName: networkName, address: address})
       if(utxos.length === 0){
           throw new Error ("no utxo outputs available")
       }
       let sat_utxo
       utxos.forEach(x => {
           if(x.txid === satTx.txid && x.vout === satTx.vout){
               sat_utxo = x
           }
       })
       return sat_utxo
   }catch(e){
       throw new Error(e.message)
   }

}

const addInput = async ({input, pubkey, addressType, index}) => {
   try{
       let vin = []
       let input_data = await getInputData({addressType: addressType, input: [input], networkName: networkName, publicKey: pubkey})
       vin[index] = input_data
       return vin
   }catch(e){
       throw new Error(e.message)
   }
}

const addOutput = async ({output, addressType, index}) => {
   try{
       let outputs = []
       output[index] = output
   }catch(e){
       throw new Error(e.message)
   }

}

const handleSatPoint = async ({satpoint, satUtxo, address, inscription, spend_utxo}) => {
   try{
       let n_satpoint = satpoint.split(":")
       if(n_satpoint.length !== 3)throw new Error ("satpoint must be in the format txid:vout:offset")   
       if(typeof n_satpoint[0] !== "string")throw new Error ("satpoint must be in the format txid:vout:offset")  
       if(typeof parseInt(n_satpoint[1]) !== "number")throw new Error ("satpoint vout should be in a number")
       if(typeof parseInt(n_satpoint[2]) !== "number")throw new Error ("satpoint offset should be in a number")

       let sat_utxo = []
       let vin = []
       let outputs = []
       satUtxo.forEach(x => {
           if(x.txid === n_satpoint[0] && x.vout === parseInt(n_satpoint[1])){
               sat_utxo = [x]
           }
       })
       if(sat_utxo.length === 0)throw new Error ("sat_utxo not found")

       vin.push({ txid: sat_utxo[0].txid, vout: sat_utxo[0].vout, value: sat_utxo[0].value })
       vin.push({ txid: spend_utxo.txid, vout: spend_utxo.vout, value: spend_utxo.value })
       
       let offset = parseInt(n_satpoint[2])
       if(offset > 330){
           outputs.push({value: offset, address: address});
           outputs.push({ value: inscription.fee + (sat_utxo[0].value - offset), address: inscription.inscriptionAddress})
       }else{
           outputs.push({ value: inscription.fee + (sat_utxo[0].value - offset), address: inscription.inscriptionAddress})
       }
       return {vin: vin, outputs: outputs}
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
}

const handleSatTx2 = async ({ networkName, sat_privateKey, inscriptions, satpoint, spend_utxo}) => {
   try{
       if(typeof satpoint !== "string")throw new Error ("satpoint must be a string")
       let vin = []
       let outputs = []
       const initData = getInitData2({privateKey: sat_privateKey, networkName: networkName})
       const address = initData.fundingAddress
       let utxos = await getUtxo({networkName: networkName, address: address})
       if(utxos.length === 0){
           throw new Error ("no sat utxo outputs available")
       }
       let sat_utxo = utxos.map(x => {
           if(x.value > 330){
               return x
           }
       })

       if(!sat_utxo){
           throw new Error ("no sat utxo outputs available")
       }

       if(satpoint){
           let satData = await handleSatPoint({satpoint: satpoint, satUtxo: sat_utxo, address: address, inscription: inscriptions[0], spend_utxo: spend_utxo})
           vin = satData.vin
           outputs = satData.outputs
       }else{
           vin.push({
               txid: sat_utxo[0].txid,
               vout: sat_utxo[0].vout,
               value: sat_utxo[0].value,
           })
           vin.push({
               txid: spend_utxo.txid,
               vout: spend_utxo.vout,
               value: spend_utxo.value,
           })
           outputs.push({value: sat_utxo[i].value - 1, address: address});
           outputs.push({ value: inscriptions[i].fee + 1, address: inscriptions[0].inscriptionAddress})
       }
       
       return {vin: vin, outputs: outputs, tap_publicKey: initData.tap_publicKey}
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
}

const getFeeOut = async ({}) => {
   try{
       let outputs = []

           if(options && options.service_fee){
               outputs.push({
                   value: options.service_fee,
                   address: options.service_address
               });
           }
           if(options && options.collection_fee){
               outputs.push({
                   value: options.collection_fee,
                   address: options.collection_address
               });
           }
   }catch(e){
       console.log(e)
   }
}

export const splitFunds = async ({filePaths, privateKey, networkName, feerate, padding, options}) => {
   try{

       if(!filePaths && !options.batch){
           throw new Error("filePaths or batch data is required")
       }else if(options.batch){
           if(!options.batch.data || options.batch.data.length === 0){
               throw new Error("batch data is required")
           }
       }
       if(!privateKey) throw new Error("privateKey is required")
       if(!networkName) throw new Error("networkName is required")
       if(!feerate) throw new Error("feerate is required")
       if(!padding) throw new Error("padding is required")

       if(options && options.sat_details && !options.batch){
           if(filePaths && filePaths.length > 1)throw new Error("special sat can only be used on one file")
           if(!options.sat_details.privateKey) throw new Error ("sat_privateKey is required")
           if(!options.sat_details.satpoint) throw new Error ("satpoint is required")
           if(typeof options.sat_details.privateKey !== "string") throw new Error ("sat_privateKey must be a string")
           if(typeof options.sat_details.satpoint !== "string")throw new Error ("satpoin must be a string")     
       }

       let initData = getInitData2({privateKey: privateKey, networkName: networkName})
       let fundingAddress = initData.fundingAddress;
       let outputs = [];
       
       let opt = options
       opt.show_insc = false
       
       let keyPair = getKeyPair({privateKey: privateKey})
       let inscData = await getInscriptions({
           filePaths: filePaths, 
           publicKey: keyPair.pubkey, 
           networkName: networkName, 
           feerate: feerate, 
           padding: padding, 
           options: opt
       })
       const inscAddr = inscData.inscriptions.map(x => x.inscriptionAddress)
       
       let total_fees = inscData.total_fees;
       let inscriptions = inscData.inscriptions;

       let vin = []
       let input = []

       const utxos = await getUtxo({address: fundingAddress, networkName: networkName})
       if(utxos.length === 0){
           throw new Error("No funds available for inscription")
       }
       let spend_utxo 
       utxos.forEach(x => {
           if(x.value >= total_fees){
               spend_utxo = x
           }
       })
       
       if(options && options.sat_details){
           let satTxData = await handleSatTx2({networkName: networkName, sat_privateKey: options.sat_details.privateKey, inscriptions: inscriptions, satpoint: options.sat_details.satpoint, spend_utxo: spend_utxo})
           vin = satTxData.vin
           let n_input = await getInputData("taproot", vin, networkName, Buffer.from(satTxData.tap_publicKey, 'hex'))
           n_input.map(x => {
               input.push(x)
           })
           outputs = satTxData.outputs   
       }else{
           vin.push({
               txid: spend_utxo.txid,
               vout: spend_utxo.vout,
               value: spend_utxo.value,
           })
           let n_input = await getInputData("taproot", [{txid: spend_utxo.txid, vout:spend_utxo.vout, value: spend_utxo.value,}], networkName, Buffer.from(initData.tap_publicKey, 'hex'))
           n_input.map(x => {
               input.push(x)
           })

           for (let i = 0; i < inscriptions.length; i++) {
               outputs.push(
                   {
                       value: inscriptions[i].fee,
                       address: inscriptions[i].inscriptionAddress
                   }
               );
           }
       }

       if(options && options.service_fee){
           outputs.push({
               value: options.service_fee,
               address: options.service_address
           });
       }
       if(options && options.collection_fee){
           outputs.push({
               value: options.collection_fee,
               address: options.collection_address
           });
       }
       
       const psbtData = getPsbtDetails({networkName:networkName, input:input, output:outputs})
       let finalized
       if(options && options.sat_details){
           //first sign satInput
           const signedTx = signTransaction2({networkName: networkName, psbt: psbtData, privateKey: options.sat_details.privateKey, addressType: "taproot", index: 0})
           //sign spend input
           finalized = signTransaction2({networkName: networkName, psbt: signedTx, privateKey: privateKey, addressType: "taproot", index: 1})
       }else{
           finalized = signTransaction2({networkName: networkName, psbt: psbtData, privateKey: privateKey, addressType: "taproot", index: 0})
       }

       let psbt_data = Psbt.fromHex(finalized.psbtHex, {network: networks[networkName]})
       let rawtx = psbt_data.extractTransaction().toHex()
       const txid = Tx.util.getTxid(rawtx)
       return {txHex: rawtx, txid: txid, inscriptionAddress: inscAddr}
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }

}

// export const splitFunds1 = async ({filePaths, privateKey, networkName, feerate, padding, options}) => {
//     try{
//         if(!filePaths || !privateKey || !networkName || !feerate || !padding){
//             throw new Error("filePaths, privateKey, networkName, feerate, and padding are required to create an inscription. Received: ", filePaths, privateKey, networkName, feerate, padding)
//         }
//         let initData = getInitData({privateKey: privateKey, networkName: networkName})
//         let fundingAddress = initData.fundingAddress;
//         let outputs = [];
       
//         let opt = options
//         opt.show_insc = false
       
//         let keyPair = getKeyPair({privateKey: privateKey})
//         let inscData = await getInscriptions({
//             filePaths: filePaths, 
//             publicKey: keyPair.pubkey, 
//             networkName: networkName, 
//             feerate: feerate, 
//             padding: padding, 
//             options: opt
//         })
       
//         let total_fees = inscData.total_fees;
//         let inscriptions = inscData.inscriptions;

//         let vin = []
//         if(options && options.satTx){
//             const sat_utxo = await handleSatTx({ 
//                 networkName: networkName, 
//                 satTx: options.satTx,
//                 address: fundingAddress,
//             })
//             if(!sat_utxo){
//                 throw new Error("satTx utxo not found")
//             }
//             vin.push({
//                 txid: sat_utxo.txid,
//                 vout: sat_utxo.vout,
//                 prevout: {
//                     value: sat_utxo.value,
//                     scriptPubKey: [ 'OP_1', initData.init_tapkey ]
//                 },
//             })

//             outputs.push(
//                 {
//                     value: inscriptions[0].fee + sat_utxo.value,
//                     scriptPubKey: [ 'OP_1', inscriptions[0].tapkey ]
//                 }
//             );
//         }else if(options && options.sat_details){
//             const n_init_redeemtx = await handleSatTx2({networkName: networkName, sat_privateKey: options.sat_details.privateKey, inscriptions: inscriptions})
//             vin[0] = n_init_redeemtx.vin[0]
//             outputs = n_init_redeemtx.vout
//         }else{
//             for (let i = 0; i < inscriptions.length; i++) {
//                 outputs.push(
//                     {
//                         value: inscriptions[i].fee,
//                         scriptPubKey: [ 'OP_1', inscriptions[i].tapkey ]
//                     }
//                 );
//             }
//         }

//         let utxos = await getUtxo({address: fundingAddress, networkName: networkName})
       
//         if(utxos.length === 0){
//             throw new Error("No funds available for inscription")
//         }
//         let spend_utxo 
//         utxos.forEach(x => {
//             if(x.value >= total_fees){
//                 spend_utxo = x
//             }else{
//                 throw new Error("Insufficient funds")
//             }
//         })

//         vin.push({
//             txid: spend_utxo.txid,
//             vout: spend_utxo.vout,
//             prevout: {
//                 value: spend_utxo.value,
//                 scriptPubKey: [ 'OP_1', initData.init_tapkey ]
//             },
//         })



//         if(options && options.service_fee){
//             outputs.push(
//                 {
//                     value: options.service_fee,
//                     scriptPubKey: [ 'OP_1', Address.p2tr.decode(options.service_address, getAddressEncoding({networkName: networkName})).hex ]
//                 }
//             );
//         }
//         if(options && options.collection_fee){
//             outputs.push(
//                 {
//                     value: options.collection_fee,
//                     scriptPubKey: [ 'OP_1', Address.p2tr.decode(options.collection_address, getAddressEncoding({networkName: networkName})).hex ]
//                 }
//             );
//         }

//         const init_redeemtx = Tx.create({
//             vin  : vin,
//             vout : outputs
//         })
       

//         //Sign the transaction
//         const pubkey = hexToBytes(initData.publicKey)
//         init_redeemtx.vin.forEach((x, index) => {
//             if(x.prevout.scriptPubKey[1] === initData.init_tapkey){
//                 const init_sig = Signer.taproot.sign(getKeyPair({privateKey:privateKey}).seckey.raw, init_redeemtx, index, {extension: initData.init_leaf});
//                 x.witness = [ init_sig.hex, [ pubkey, 'OP_CHECKSIG'], initData.init_cblock ]
//             }
//         })
              
//         let rawtx = Tx.encode(init_redeemtx).hex;
//         const txid = Tx.util.getTxid(Tx.encode(init_redeemtx))
//         return {txHex: rawtx, txid: txid}
//     }catch(e){
//         console.log(e)
//         throw new Error(e.message)
//     }

// }

const createBatchInscribeTx = async ({inscription, receiveAddress, privateKey, networkName, options}) => {
   try{
       const addressEncoding = getAddressEncoding({networkName: networkName})
       const utxos = await getUtxo({address: inscription.inscriptionAddress, networkName: networkName})
       if(utxos.length === 0){
           throw new Error("No funds available for inscription")
       }
       let spend_utxo 
       utxos.forEach(x => {
           if(x.value >= inscription.fee){
               spend_utxo = x
           }
       })
       
       const vin = [{
           txid: spend_utxo.txid,
           vout: spend_utxo.vout,
           prevout: {
               value: spend_utxo.value,
               scriptPubKey: [ 'OP_1', Address.p2tr.decode(inscription.inscriptionAddress, addressEncoding).hex ]
           },
       }]
       const vout = options.batch.data.map(x => {
           return {
               value: inscription.padding,
               scriptPubKey: [ 'OP_1', Address.p2tr.decode(receiveAddress, addressEncoding).hex ]
           }
       })

       const redeemtx = Tx.create({
           vin  : vin,
           vout : vout,
       });

       let transactions = []

       const sig = Signer.taproot.sign(getKeyPair({privateKey:privateKey}).seckey.raw, redeemtx, 0, {extension: inscription.leaf});
       redeemtx.vin[0].witness = [ sig.hex, inscription.script_orig, inscription.cblock ];
       let rawtx = Tx.encode(redeemtx).hex;
       const txid = Tx.util.getTxid(Tx.encode(redeemtx))
       let ids = []
       options.batch.data.forEach((x, i) => {
           ids.push(`${txid}i${i}`)
       })
       transactions.push({txid: txid, txHex: rawtx, id: ids})
       return transactions    
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
}

const createInscribeTx = async ({inscriptions, receiveAddress, privateKey, networkName}) => {
   try{
       let transactions = []
       for (let i = 0; i < inscriptions.length; i++) {
           let inscription = inscriptions[i]
           let addressEncoding = getAddressEncoding({networkName: networkName})
           let utxos = await getUtxo({address: inscription.inscriptionAddress, networkName: networkName})
           if(utxos.length === 0){
               throw new Error("No funds available for inscription")
           }
           
           let spend_utxo 
           utxos.forEach(x => {
               if(x.value >= inscriptions[i].fee){
                   spend_utxo = x
               }
           })

           const redeemtx = Tx.create({
               vin  : [{
                   txid: spend_utxo.txid,
                   vout: spend_utxo.vout,
                   prevout: {
                       value: spend_utxo.value,
                       scriptPubKey: [ 'OP_1', Address.p2tr.decode(inscription.inscriptionAddress, addressEncoding).hex ]
                   },
               }],
               vout : [{
                   value: inscription.padding,
                   scriptPubKey: [ 'OP_1', Address.p2tr.decode(receiveAddress, addressEncoding).hex ]
               }],
           });

           const sig = Signer.taproot.sign(getKeyPair({privateKey:privateKey}).seckey.raw, redeemtx, 0, {extension: inscription.leaf});
           redeemtx.vin[0].witness = [ sig.hex, inscription.script_orig, inscription.cblock ];
           let rawtx = Tx.encode(redeemtx).hex;
           const txid = Tx.util.getTxid(Tx.encode(redeemtx))
           transactions.push({txid: txid, txHex: rawtx, id: `${txid}i${i}`})
       }
       return transactions
   }catch(e){
       console.log(e)
   }
}

export const createInscribeTransactions = async ({filePaths, privateKey, receiveAddress, networkName, feerate, padding, options}) => {
   try{

       if(!filePaths && !options.batch){
           throw new Error("filePaths or batch data is required")
       }else if(options.batch){
           if(!options.batch.data || options.batch.data.length === 0){
               throw new Error("batch data is required")
           }
       }
       if(!privateKey) throw new Error("privateKey is required")
       if(!receiveAddress) throw new Error("receiveAddress is required")
       if(!networkName) throw new Error("networkName is required")
       if(!feerate) throw new Error("feerate is required")
       if(!padding) throw new Error("padding is required")

       const keyPair = getKeyPair({privateKey: privateKey})
       let inscription_data = await getInscriptions({
           filePaths: filePaths, 
           publicKey: keyPair.pubkey,
           networkName: networkName, 
           feerate: feerate, 
           padding: padding, 
           options: options
       })

       let inscriptions = inscription_data.inscriptions
       let transactions = []
       if(options && options.batch){
           const inscription = inscriptions[0]
           transactions = await createBatchInscribeTx({inscription: inscription, receiveAddress: receiveAddress, privateKey: privateKey, networkName: networkName, options:options})
       }else{
           transactions = await createInscribeTx({inscriptions: inscriptions, receiveAddress: receiveAddress, privateKey: privateKey, networkName: networkName})
       }
       
       return transactions
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
}

//helper Functions
const byteChecker = async ({files, fileHash}) => {

   let inscribed_already = [];
   let errors = [];

   if(files && fileHash){
       console.log("byteChecker takes either an array of file objects OR an array of SHA256 hashes");
   }

   if(files){
       for (let i = 0; i < files.length; i++) {
           let response = await axios.get('https://api.ordinalsbot.com/search?hash=' + files[i].sha256);
           let hash_result = response.data
           try {
               if (hash_result.results.length != 0) {
                   inscribed_already.push(files[i].name);
               }
           } catch (e) {
               errors.push(files[i].name);
           }
           await sleep(1000);
       }
   }else if(fileHash){
       for (let i = 0; i < fileHash.length; i++) {
           let response = await axios.get('https://api.ordinalsbot.com/search?hash=' + fileHash[i]);
           let hash_result = response.data
           try{
               if(hash_result.results.length !== 0) inscribed_already.push(fileHash[i]);
           }catch(e){
               errors.push(fileHash[i]);
           }
           await sleep(1000);
       }    
   }

   return {
       inscribed: inscribed_already,
       errors: errors
   }

}

async function addressReceivedMoneyInThisTx({address, networkName}) {
   let txid;
   let vout;
   let amt;
   let addressData;

   try
   {
       let {addresses} = await init(networkName)
       addressData = await addresses.getAddressTxs({address: address})
   }
   catch(e)
   {
       addressData = await axios.get("https://blockstream.info/api/address/" + address + "/txs");
   }
   addressData.forEach(function (tx) {
       tx["vout"].forEach(function (output, index) {
           if (output["scriptpubkey_address"] == address) {
               txid = tx["txid"];
               vout = index;
               amt = output["value"];
           }
       });
   });
   return [txid, vout, amt];
}

//includeMempool = bool
async function addressOnceHadMoney({address, networkName, includeMempool}) {
   let url;
   let addressData;

   try
   {
       const { addresses } = await init(networkName)
       addressData = await addresses.getAddress({address: address})
   }
   catch(e)
   {
       if(networkName == 'mainnet')
       {
           url = "https://blockstream.info/api/address/" + address;
           let response = await axios.get(url);
           addressData = response.data
       }
   }

   if (addressData["chain_stats"]["tx_count"] > 0 || (includeMempool && addressData["mempool_stats"]["tx_count"] > 0)) {
       return true;
   }
   return false;
}


async function encodeBase64(file) {
   const res =  new Promise(function (resolve, reject) {
       let imgReader = new FileReader();
       const readFile = function (event) {
           const buffer = imgReader.result
           resolve(buffer)
       }

       imgReader.addEventListener('load', readFile)
       imgReader.readAsDataURL(file)
       
   });
   return res
}


function base64ToHex(str) {
   const raw = atob(str);
   let result = '';
   for (let i = 0; i < raw.length; i++) {
       const hex = raw.charCodeAt(i).toString(16);
       result += (hex.length === 2 ? hex : '0' + hex);
   }
   return result.toLowerCase();
}

function buf2hex(buffer) { // buffer is an ArrayBuffer
   return [...new Uint8Array(buffer)]
       .map(x => x.toString(16).padStart(2, '0'))
       .join('');
}

function hexToBytes(hex) {
   return Uint8Array.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function bytesToHex(bytes) {
   return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
}

function textToHex(text) {
   var encoder = new TextEncoder().encode(text);
   return [...new Uint8Array(encoder)]
       .map(x => x.toString(16).padStart(2, "0"))
       .join("");
}

function arrayBufferToBuffer(ab) {
   var buffer = buf.Buffer.alloc(ab.byteLength)
   var view = new Uint8Array(ab)
   for (var i = 0; i < buffer.length; ++i) {
       buffer[i] = view[i]
   }
   return buffer
}

function hexString(buffer) {
   const byteArray = new Uint8Array(buffer)
   const hexCodes = [...byteArray].map(value => {
       return value.toString(16).padStart(2, '0')
   })

   return '0x' + hexCodes.join('')
}

async function fileToArrayBuffer(file) {
   const res = new Promise(function (resolve, reject) {
       const reader = new FileReader()
       const readFile = function (event) {
           const buffer = reader.result
           resolve(buffer)
       }

       reader.addEventListener('load', readFile)
       reader.readAsArrayBuffer(file)
   })
   return res
}

async function bufferToSha256(buffer) {
   return crypto.subtle.digest('SHA-256', buffer)
}

async function fileToSha256Hex(file) {
   const buffer = await fileToArrayBuffer(file)
   const hash = await bufferToSha256(arrayBufferToBuffer(buffer))
   return hexString(hash)
}

function getMimeType(fileExtension) {
   const mimeType = mimeTypes.lookup(fileExtension);
   return mimeType || 'application/octet-stream'; // Default to binary data if MIME type is not found
}

function waitSomeSeconds(number) {
   let num = number.toString() + "000";
   num = Number(num);
   return new Promise(function (resolve, reject) {
       setTimeout(function () {
           resolve("");
       }, num);
   });
}

async function isPushing() {
   while (pushing) {
       await sleep(10);
   }
}

function sleep(ms) {

   return new Promise(resolve => setTimeout(resolve, ms));
}

//in txt format create a documentation for all the exported functions in this file
//create a test file for all the functions in this file

// let sat_publicKey = "599c854e207dd1a9366f8f25e46e2c0532d42deed9c75fda3399039340978798"
// let sat_privateKey = "e9adb088a32b7ac0af6b459e3339795a89a7f26046eb342d5ba0e06a54e49e99"
// let satFundAddr = "tb1pq6mls2dazea494r2sz67qy9c608fmh5nzmf4zkz5efs6yt9k8sqsxywmce"

// let sat_details = {
//     privateKey: sat_privateKey, 
//     satpoint: "7d2f34fec10956e3025a8a02707a7bff9d4eaa841b2baadfedd40e31ce8c1a17:0:994"
// }

// let batchData = {
//     data: [
//         {
//             file: `${process.cwd()}/testImg/1.png`,
//             receiveAddress: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h",
//             metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz", description: "batch inscription on a specific sat type"},
//             size: 472    
//         },
//         {
//             file: `${process.cwd()}/testImg/2.png`,
//             receiveAddress: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h",
//             metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz", description: "batch inscription on a specific sat type"},
//             size: 490    
//         }
//     ]
// }

// const options = {   
//     service_fee: 2000, 
//     service_address: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", 
//     collection_fee: 1000, 
//     collection_address: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", 
//     metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz", description: "simulating special sat inscription"},
//     //sat_details: sat_details,   
//     //batch: batchData,
// }

// let filePaths = [`${process.cwd()}/testImg/1.png`, `${process.cwd()}/testImg/2.png`]
// let feeRate = 5
// let padding = 550
// let publicKey = "5d26301ee6d5ab78b4b2490d3f82870519acf628220aed08e70c3034790e5d18"
// let privateKey = "60cfae86055fe2e4813f08e07ffeb0f2cd317131588c1501459c4c7c6850d31a"
// let insc_fundAddr = "tb1p68yyyly3jwgrkwvz2x7wjzujndkwd6uejqtev2dh07s4qtsp4dpq3aktad"


// getInscriptions({
//     filePaths: filePaths, 
//     publicKey: publicKey, 
//     networkName: "testnet", 
//     feerate: feeRate, 
//     padding: padding, 
//     options: options 
// }).then(res => {
//     console.log(res)
// }).catch()

// splitFunds({privateKey: privateKey, networkName: "testnet", feerate: feeRate, padding: padding, options: options}).then(res => {
//     console.log(res)
// }).catch()

// createInscribeTransactions({privateKey:privateKey, receiveAddress:"tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", networkName:"testnet", feerate:feeRate, padding:padding, options:options}).then(res => {
//     console.log(res)
// }).catch()

//console.log(getInitData2({networkName: "testnet", privateKey: privateKey, addressType: "taproot"}))

//console.log(getKeyPair({networkName: "testnet"}))

// console.log(getInscriptionCost({
//     fileSizes: [472, 490], 
//     feerate: feeRate, 
//     padding: 550, 
//     options: options
// }))

//console.log(getAllAddress({privateKey: "9c45ef6897c0588477ddf51325ea10203168e06a2ffbc2586c0878364f82012f", networkName: "testnet"}))
