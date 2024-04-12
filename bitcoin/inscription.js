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
           if(!mimetype) throw new Error ("file type not supported: ", path.extname(file[i]))

           let _file = {name: filename, path: filePath, size:fileSize, type:mimetype }

           if (file[i].size >= 350000) {
               throw new Error ("file size exceeds limit: ", file[i])
           } 

           let b64;

           if (mimetype === "text/plain" || mimetype === "text/html" || mimetype === "text/javascript" || mimeTypes === "text/markdown"){
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

const createInscriptionScript = ({pubkey, mimetype, data, metadata, deligate}) => {
   try{
       const ec = new TextEncoder();
       if(!pubkey){
           throw new Error ("pubkey, mimetype, and data are required to create an inscription script. Received: ", pubkey)
       }
       
       let script = [ 
            pubkey,
            'OP_CHECKSIG',
            'OP_0',
            'OP_IF',
            ec.encode('ord'),
        ];
       let script_backup = [];

       if(deligate){
            if(!deligate.id) throw new Error ("deligate id is required")
            const deligateData = getDeligateData(deligate.id)
            let deligateScript = []
            if(!deligate.fileType){
                const deligateData = getDeligateData(deligate.id)
                deligateScript = ['0b', deligateData.serilizedId]
            }else{
                let mimetype = getMimeType(deligate.fileType);
                if(!mimetype) throw new Error ("file type not supported: ", deligate.fileType)
                if(mimetype === "text/plain" || mimetype === "text/html" || mimetype === "text/javascript" || mimetype === "text/markdown"){
                    mimetype += ";charset=utf-8";
                }
                deligateScript = ['01', ec.encode(mimetype), '0b', deligateData.serilizedId]
            }
            script = script.concat(deligateScript)
            if(metadata){
                const metadataScript = ['05', Uint8Array.from(covertJsonToCbor(metadata))]
                script = script.concat(metadataScript)
            }
        }else{
            if(!mimetype){
                throw new Error ("mimetype is required to create an inscription script. Received: ", mimetype)
            }
            if(!data){
                throw new Error ("data is required to create an inscription script. Received: ", data)
            }
            if(metadata){
                const metadataScript = ['05', Uint8Array.from(covertJsonToCbor(metadata))]
                script = script.concat(metadataScript)
            }
            const dataScript = ['01', mimetype, 'OP_0', data]
            script = script.concat(dataScript)
        }
        script.push('OP_ENDIF')

        
    //    if(deligate){
    //         script = [
    //             pubkey,
    //             'OP_CHECKSIG',
    //             'OP_0',
    //             'OP_IF',
    //             ec.encode('ord'),
    //             '11',
    //             //add the serilized deligate id
    //             'OP_ENDIF'
    //         ];

    //         script_backup = [
    //             '0x' + buf2hex(pubkey.buffer),
    //             'OP_CHECKSIG',
    //             'OP_0',
    //             'OP_IF',
    //             '0x' + buf2hex(ec.encode('ord')),
    //             'OP_ENDIF'
    //         ];
    //         return {
    //         script: script,
    //         script_backup: script_backup
    //         }
    //    }
       
    //    if(metadata){
    //         script = [
    //             pubkey,
    //             'OP_CHECKSIG',
    //             'OP_0',
    //             'OP_IF',
    //             ec.encode('ord'),
    //             '01',
    //             mimetype,
    //             '05',
    //             Uint8Array.from(covertJsonToCbor(metadata)), //CBOR
    //             'OP_0',
    //             data,
    //             'OP_ENDIF'
    //         ];

    //         script_backup = [
    //             '0x' + buf2hex(pubkey.buffer),
    //             'OP_CHECKSIG',
    //             'OP_0',
    //             'OP_IF',
    //             '0x' + buf2hex(ec.encode('ord')),
    //             '01',
    //             '0x' + buf2hex(mimetype),
    //             '05',
    //             '0x' + buf2hex(Uint8Array.from(covertJsonToCbor(metadata))), //CBOR
    //             'OP_0',
    //             '0x' + buf2hex(data),
    //             'OP_ENDIF'
    //         ];
    //        return {
    //            script: script,
    //            script_backup: script_backup
    //        }
    //    }

    //    script = [ 
    //         pubkey,
    //         'OP_CHECKSIG',
    //         'OP_0',
    //         'OP_IF',
    //         ec.encode('ord'),
    //         '01',
    //         mimetype,
    //         'OP_0',
    //         data,
    //         'OP_ENDIF'
    //     ];

    //     script_backup = [
    //         '0x' + buf2hex(pubkey.buffer),
    //         'OP_CHECKSIG',
    //         'OP_0',
    //         'OP_IF',
    //         '0x' + buf2hex(ec.encode('ord')),
    //         '01',
    //         '0x' + buf2hex(mimetype),
    //         'OP_0',
    //         '0x' + buf2hex(data),
    //         'OP_ENDIF'
    //     ];

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
       
       inscriptionData.map((x, index) => {
            let _script = ['OP_0', 'OP_IF', ec.encode('ord')]
           //the pointer should be in little endian with trailing zeros ignored
           const little_endian = toLittleEndian(index)
           let pointer =  Uint8Array.from(bytesToHex(little_endian).replace(/00/g, ''))

           let pointerScript = []
           
            pointerScript = ['02', pointer]
            _script = _script.concat(pointerScript)
           
           if(x.deligate){
                if(!x.deligate.id) throw new Error ("deligate id is required")
                if(!x.deligate.fileType) throw new Error ("deligate fileType is required")
                let mimetype = getMimeType(x.deligate.fileType);
                if(!mimetype) throw new Error ("file type not supported: ", x.deligate.fileType)
                if(mimetype === "text/plain" || mimetype === "text/html" || mimetype === "text/javascript" || mimetype === "text/markdown"){
                    mimetype += ";charset=utf-8";
                }
                const deligateData = getDeligateData(x.deligate.id)
                const deligateScript = ['01', ec.encode(mimetype), '0b', deligateData.serilizedId]
                _script = _script.concat(deligateScript)
                if(x.metadata){
                    const metadataScript = ['05', Uint8Array.from(covertJsonToCbor(x.metadata))]
                    _script = _script.concat(metadataScript)
                }    
            }else{
                const data = hexToBytes(x.fileData.hex)
                const mimetype = ec.encode(x.fileData.mimetype);
                if(x.metadata){
                    const metadataScript = ['05', Uint8Array.from(covertJsonToCbor(x.metadata))]
                    _script = _script.concat(metadataScript)
                }
    
                if(data){
                    if(!mimetype){
                        throw new Error ("mimetype is required to create an inscription script. Received: ", mimetype)
                    }
                    const dataScript = ['01', mimetype, 'OP_0', data]
                    _script = _script.concat(dataScript)
                }
            }
            _script.push('OP_ENDIF')
            script = script.concat(_script)
       })
       // add the header to the script
       script = spriptHeader.concat(script)
       script_backup = scriptBackupHeader.concat(script_backup)

       return { script: script, script_backup: script_backup }

   }catch(e){
       console.log(e)
       return {status: false, message: e.message}
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
       if(!publicKey) return {status: false, message: "publicKey is required"}
       if(!feerate) return {status: false, message: "feerate is required"}
       if(!networkName) return {status: false, message: "networkName is required"}
       
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

       let data;
       if(options && options.deligate){
            if(!options.deligate.id) return {status: false, message: "deligate id is required"} 
            let scriptData;
            if(options.metadata){
                scriptData = createInscriptionScript({pubkey: pubkey, deligate: options.deligate, metadata: options.metadata})
            }else{
                scriptData = createInscriptionScript({pubkey: pubkey, deligate: options.deligate})
            }
            script = scriptData.script;
            script_backup = scriptData.script_backup;
            //extra_bytes += 80
        }else{
            if(!files) return {status: false, message: "files is required"}
            const hex = files.hex;
            data = hexToBytes(hex);
            const mimetype = ec.encode(files.mimetype);
            let scriptData;
            if(options && options.metadata){
                scriptData = createInscriptionScript({pubkey: pubkey, mimetype: mimetype, data: data, metadata: options.metadata})
            }else{
                scriptData = createInscriptionScript({pubkey: pubkey, mimetype: mimetype, data: data})
            }
            script = scriptData.script;
            script_backup = scriptData.script_backup;
            //extra_bytes += 80
        }

       const leaf = Tap.encodeScript(script);
       const [tapkey, cblock] = Tap.getPubKey(pubkey, { target: leaf });

       const inscriptionAddress = Address.p2tr.encode(tapkey, addressEncoding);        
       const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;

       const _extra_bytes = extra_bytes * feerate
      
       let txsize = 0
       if(options && options.deligate){
            txsize = _extra_bytes + Math.ceil(0 / 4) * feerate;
       }else{
            txsize = _extra_bytes + Math.ceil(data.length / 4) * feerate;
       }
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
    console.log(e)
       throw new Error(e)
   }
}

const getBatchInscription = async ({publicKey, networkName, feerate, padding, batch}) => {
   try{
       const ec = new TextEncoder();
       if(!publicKey) return {status: false, message: "publicKey is required"}
       if(!networkName) return {status: false, message: "networkName is required"}
       if(!feerate) return {status: false, message: "feerate is required"}

       let pubkey = hexToBytes(publicKey);
       let addressEncoding = getAddressEncoding({networkName: networkName})
       let pad
       if(!padding || padding < 550){
           pad = 550
       }else{
           pad = padding
       }

       let extra_bytes = 80;
       if(!batch) return {status: false, message: "batch data is required"}
       if(!batch.data || batch.data.length === 0) return {status: false, message: "batch data is required"}
        if(batch.parent) inputs += 1


        let totalSize = 0
        let _padding = 0
        let files = []
        let data = {}
        let incs_file_data = []
        batch.data.map(x => {
            let _data = {}
            if(x.deligate){
                if(!x.deligate.id) return {status: false, message: "deligate id is required"}
                _data.deligate = x.deligate
                _data.size = 0
                totalSize += _data.size
                _padding += pad
                if(x.metadata){
                    extra_bytes += 80
                    _data.metadata = x.metadata;
                }   
                incs_file_data.push(_data)
            }else{
                files = batch.data.map(x => x.file)
            }
        })
        
        //This handles batch without deligate
        let _file = await getFileData(files)
        _file.map((x, i) => {
            data.fileData = x;
            data.size = hexToBytes(x.hex).length;
            totalSize += data.size
            _padding += pad
            if(batch.data[i].metadata){
                extra_bytes += 80
                data.metadata = x.metadata
            } 
            incs_file_data.push(data)
        })
       
       const {script, script_backup} = createBatchInscriptionScript({pubkey: pubkey, inscriptionData: incs_file_data})
       const leaf = Tap.encodeScript(script);
       const [tapkey, cblock] = Tap.getPubKey(pubkey, { target: leaf });
       const inscriptionAddress = Address.p2tr.encode(tapkey, addressEncoding);
       
       let inputCount = 1
       let prefix = getTransactionSize({input:inputCount, output:[{outputType: "P2TR", count: batch.data.length}], addressType: "taptoot"}).txVBytes * feerate;
       
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
       return {status: false, message: e.message}
   }

}

export const getInscriptionCost = ({fileSizes, feerate, padding, options, batch}) => {
   try{ 

        let inputs = 1
        let outputCount = 0 
        let total_fees = 0
        let fileCount = 0
        let extra_bytes = 80

        if(options && options.deligate){
            if(!options.deligate.id) return {status: false, message: "deligate id is required"}
        }else{
            if(!fileSizes && !batch) return {status: false, message: "fileSizes or batch data is required"}
        }
        if(!feerate) return {status: false, message: "feerate is required"}
        let pad
        if(!padding || padding < 550){
            pad = 550
        }else{
            pad = padding
        }

        if(batch){
            let totalSize = 0
            let _padding = 0
            if(batch.data.length === 0) return {status: false, message: "batch data is empty"}
            if(batch.parent) {
                inputs += 1
                outputCount += 1
            }
            batch.data.map(x => {
                _padding += pad
                if(x.metadata) extra_bytes += 80
                if(x.deligate){
                    totalSize += 0
                }else{
                    totalSize += x.size
                } 
            })
            fileCount = batch.data.length
            const _extra_bytes = extra_bytes * feerate
            const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: fileCount}], addressType: "taptoot"}).txVBytes * feerate;
            const txsize = _extra_bytes + Math.ceil(totalSize / 4) * feerate;
            const fee = txsize + prefix + _padding;
            total_fees += fee;
            outputCount += fileCount
        }else{
            let txsize = 0
            if(options && options.deligate){
                txsize = Math.ceil(0 / 4) * feerate;
                fileCount = 1
            }else{
                if(fileSizes.length === 0) return {status: false, message: "fileSizes is empty"}
                fileCount = fileSizes.length
                for (let i = 0; i < fileSizes.length; i++) {
                    txsize = Math.ceil(fileSizes[i] / 4) * feerate;
                }
            }

            for (let i = 0; i < fileCount; i++) {
                const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
                if(options && options.metadata) {
                    const _extra_bytes = 80 * feerate
                    txsize =  _extra_bytes + txsize
                }
                const fee =  txsize + prefix + pad;
                total_fees += fee;
                outputCount += 1
            } 

            if(options && options.sat_details) {
                inputs += 1
                outputCount += 1
            } 
        }
       if(fileCount === 0) return {status: false, message: "filesize of batch data is empty"}
       if(options && options.service_fee){
           if(!options.service_address) return {status: false, message: "service_address is required to add a service fee"}
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += (options.service_fee) + prefix
           outputCount += 1
       }

       if(options && options.collection_fee){
           if(!options.collection_address) return {status: false, message: "collection_address is required to add a collection fee"}
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += (options.collection_fee) + prefix
           outputCount += 1
       }
       
        let extraSize = 80 * fileCount * feerate
       let outFeeData = [{outputType: "P2TR", count: outputCount}]
       const totalSize = getTransactionSize({input: inputs, output:outFeeData, addressType: "taptoot"}).txVBytes * feerate;
       //add extra size to the total fees
       total_fees += totalSize + extraSize
       return total_fees
   }catch(e){
       console.log(e)
        return {status: false, message: e.message}
   }
}

export const getInscriptions = async ({filePaths, publicKey, networkName, feerate, padding, options, batch}) => {
   try{ 

        let inscriptions = [];
        let inputs = 1
        let outputCount = 0
        let total_fees = 0
        let fileCount = 0

        if(options && options.deligate){
            if(!options.deligate.id) return {status: false, message: "deligate id is required"}
        }
        if(options && options.sat_details) {
            inputs += 1
            outputCount += 1
        } 
       if(!publicKey) return {status: false, message: "publicKey is required"}
       if(!networkName) return {status: false, message: "networkName is required"}
       if(!feerate) return {status: false, message: "feerate is required"}

       if(batch){
           if(!batch.data || batch.data.length === 0)  return {status: false, message: "batch data is required"}
           if(batch.parent) inputs += 1
           let inscData = await getBatchInscription({publicKey: publicKey, networkName: networkName, feerate: feerate, padding: padding, batch: batch})
           inscriptions.push(inscData)
           total_fees += inscData.fee
           
           fileCount = batch.data.length
           outputCount += batch.data.length
       }else{
            let files = []
            if(options && options.deligate){
                fileCount = 1
            }else{
                if(!filePaths) return {status: false, message: "filePaths is required"}
                fileCount = filePaths.length
                files = await getFileData(filePaths)
                if(fileCount > 1 && options.sat_details) return {status: false, message: `inscription on special sat can only be done on one file, you have ${fileCount} files`}
            }
            
           for (let i = 0; i < fileCount; i++) {
                let inscription
                if(options && options.deligate){
                    inscription = _getInscription({files: null, publicKey: publicKey, networkName: networkName, feerate: feerate, padding: padding, options: options})
                }else{
                    inscription = _getInscription({files: files[i], publicKey: publicKey, networkName: networkName, feerate: feerate, padding: padding, options: options})
                }
               inscriptions.push(inscription)
               total_fees += inscription.fee
               outputCount += 1
           }
           if(options && options.sat_details){
                if(typeof options.sat_details.privateKey !== "string") return {status: false, message: "sat_details privateKey is required"}
            }
       }
       
       if(options && options.service_fee){
           if(!options.service_address) return {status: false, message: "service_address is required to add a service fee"}
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += options.service_fee + prefix
           outputCount += 1
       }
       if(options && options.collection_fee){
           if(!options.collection_address) return {status: false, message: "collection_address is required to add a collection fee"}
           const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txVBytes * feerate;
           total_fees += options.collection_fee + prefix
           outputCount += 1
       }
       
       let extraSize = 80 * fileCount * feerate
       let outFeeData = [{outputType: "P2TR", count: outputCount}]
       let totalSize = getTransactionSize({input: inputs, output:outFeeData, addressType: "taptoot"}).txVBytes*feerate
     
       //add extra size to the total fees
       total_fees += totalSize + extraSize

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
       return {status: false, message: e.message}
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

const handleSatPoint = async ({satpoint, satUtxo, address, inscription, spend_utxo, addToIns}) => {
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
           outputs.push({ value: addToIns + inscription.fee + (sat_utxo[0].value - offset), address: inscription.inscriptionAddress})
       }else{
           outputs.push({ value: addToIns + inscription.fee + (sat_utxo[0].value - offset), address: inscription.inscriptionAddress})
       }
       return {vin: vin, outputs: outputs}
   }catch(e){
       console.log(e)
       throw new Error(e.message)
   }
}

const handleSatTx2 = async ({ networkName, sat_privateKey, inscriptions, satpoint, spend_utxo, addToIns}) => {
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
           let satData = await handleSatPoint({satpoint: satpoint, satUtxo: sat_utxo, address: address, inscription: inscriptions[0], spend_utxo: spend_utxo, addToIns: addToIns})
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
           outputs.push({ value: addToIns + inscriptions[i].fee + 1, address: inscriptions[0].inscriptionAddress})
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

export const splitFunds = async ({filePaths, privateKey, networkName, feerate, padding, options, batch}) => {
   try{ 
       if(!privateKey) return {status: false, message: "privateKey is required"}
       if(!networkName) return {status: false, message: "networkName is required"}
       if(!feerate) return {status: false, message: "feerate is required"}
       if(!padding) return {status: false, message: "padding is required"}

       if(batch){
            if(!batch.data || batch.data.length === 0){
                return {status: false, message: "batch data is required"}
            }
        }

       if(options && options.sat_details && !batch){
           if(filePaths && filePaths.length > 1) return {status: false, message: "special sat can only be used on one file"}
           if(!options.sat_details.privateKey) return {status: false, message: "sat_privateKey is required"}
           if(!options.sat_details.satpoint) return {status: false, message: "satpoint is required"}
           if(typeof options.sat_details.privateKey !== "string") return {status: false, message: "sat_privateKey must be a string"}
           if(typeof options.sat_details.satpoint !== "string") return {status: false, message: "satpoint must be a string"}  
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
           options: opt,
           batch: batch ? batch : null
       })
       const inscAddr = inscData.inscriptions.map(x => x.inscriptionAddress)
       
       let total_fees = inscData.total_fees;
       let inscriptions = inscData.inscriptions;

       let vin = []
       let input = []
       
       const utxos = await getUtxo({address: fundingAddress, networkName: networkName})
       if(utxos.length === 0){
           return {status: false, message: "No funds available for inscription"}
       }
       let spend_utxo = null
       utxos.forEach(x => {
           if(x.value >= total_fees){
               spend_utxo = x
           }
       })
       if(spend_utxo === null){
            return {status: false, message: "No funds available for inscription"}
        }
       
       //get transaction cost
       let out_count = 1
       let ins_count = 1
       if(options && options.service_fee) out_count += 1
       if(options && options.collection_fee) out_count += 1
       if(options && options.sat_details) {
            out_count += 1
            ins_count += 1
        }

       const _txSize = getTransactionSize({input: ins_count, output: [{outputType: "P2TR", count: out_count}], addressType: "taproot"}).txVBytes
       const splitTxFee = _txSize * feerate
       
       const pad = inscriptions.reduce((acc, x) => acc + x.fee, 0)
       const serviceAmount = options && options.service_fee ? options.service_fee : 0
       const collectionAmount = options && options.collection_fee ? options.collection_fee : 0
       const addToInscription = (spend_utxo.value - splitTxFee - pad - serviceAmount - collectionAmount) / inscriptions.length
       
        if(options && options.sat_details){
           let satTxData = await handleSatTx2({networkName: networkName, sat_privateKey: options.sat_details.privateKey, inscriptions: inscriptions, satpoint: options.sat_details.satpoint, spend_utxo: spend_utxo, addToIns: addToInscription})
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
                        value: inscriptions[i].fee + addToInscription,
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
         return {status: false, message: e.message}
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

const createBatchInscribeTx = async ({inscription, receiveAddress, privateKey, networkName, batch}) => {
   try{
       const addressEncoding = getAddressEncoding({networkName: networkName})
       const utxos = await getUtxo({address: inscription.inscriptionAddress, networkName: networkName})
       if(utxos.length === 0){
           return {status: false, message: "No funds available for inscription"}
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
       const vout = batch.data.map(x => {
           return {
               value: inscription.padding,
               scriptPubKey: [ 'OP_1', Address.p2tr.decode(x.receiveAddress, addressEncoding).hex ]
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
       batch.data.forEach((x, i) => {
           ids.push(`${txid}i${i}`)
       })
       transactions.push({txid: txid, txHex: rawtx, id: ids})
       return transactions    
   }catch(e){
       console.log(e)
       return {status: false, message: e.message}
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
           
           let spend_utxo = null
           utxos.forEach(x => {
               if(x.value >= inscriptions[i].fee){
                   spend_utxo = x
               }
           })

           if(spend_utxo === null){
                throw new Error("No funds available for inscription")
           }
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

export const createInscribeTransactions = async ({filePaths, privateKey, receiveAddress, networkName, feerate, padding, options, batch}) => {
   try{

       if(batch){
           if(!batch.data || batch.data.length === 0){
               return {status: false, message: "batch data is required"}
           }
       }
       if(!privateKey) return {status: false, message: "privateKey is required"}
       if(!receiveAddress) return {status: false, message: "receiveAddress is required"}
       if(!networkName) return {status: false, message: "networkName is required"}
       if(!feerate) return {status: false, message: "feerate is required"}
       if(!padding) return {status: false, message: "padding is required"}

       const keyPair = getKeyPair({privateKey: privateKey})
       let inscription_data = await getInscriptions({
           filePaths: filePaths, 
           publicKey: keyPair.pubkey,
           networkName: networkName, 
           feerate: feerate, 
           padding: padding, 
           options: options,
            batch: batch ? batch : null
       })

       let inscriptions = inscription_data.inscriptions
       let transactions = []
       if(batch){
           const inscription = inscriptions[0]
           transactions = await createBatchInscribeTx({inscription: inscription, receiveAddress: receiveAddress, privateKey: privateKey, networkName: networkName, batch: batch})
       }else{
           transactions = await createInscribeTx({inscriptions: inscriptions, receiveAddress: receiveAddress, privateKey: privateKey, networkName: networkName})
       }
       
       return transactions
   }catch(e){
       console.log(e)
       return {status: false, message: e.message}
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
   return mimeType
}

function toLittleEndian(integer) {
    const bytes = [];
    for (let i = 0; i < 4; i++) {
        bytes.push(integer & 0xFF); // Extract the least significant byte
        integer >>= 8; // Shift right by 8 bits to get the next byte
    }
    return bytes;
}

function getDeligateData(id) {
    const match = id.match(/i(\d+)$/);
    const index = parseInt(match[1]);
    const txId = id.substring(0, match.index); 
    
    //convert the txid to bytes(uint8Array) and reverse it
    const serilizedBytes = hexToBytes(txId)
    serilizedBytes.reverse()
    
    //convert the index to little endian
    const littleEndianIndex = Uint8Array.from(toLittleEndian(index))
    
    // combine the serilizedBytes and littleEndianIndex into one Uint8Array
    let result =  new Uint8Array(serilizedBytes.length + littleEndianIndex.length)
    result.set(serilizedBytes, 0)
    result.set(littleEndianIndex, serilizedBytes.length)
    
    // convert the result to hex
    const serilizedHex = bytesToHex(result)
    // remove trailing zeros from serilizedHex and assign to result
    result = serilizedHex.replace(/00+$/, '')
    // convert the result to bytes
    result = hexToBytes(result)
    return { txId, index , serilizedId: result};
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

let sat_publicKey = "d1144b067ef1682ee40ed67ed3821783b1edb59f5ae0e23573888dbbe6954618"
let sat_privateKey = "870d748d23b9854a4c679df75db51124fbf9bcc46e5f51990716f29ce980f4ad"
let satFundAddr = "tb1pg7e4pyyynqc2n9w8v7teccw24ty4vv3hgxadh42n3dpc96u867vsv3memx"

let sat_details = {
    privateKey: sat_privateKey, 
    satpoint: "6d14b28c143b020d9680f76666c357ec86ac9a9d119d07a15690bd813fb69976:0:994"
}

let batchData = {
    data: [
        {   
            deligate: {
                id: "6299259000e0c44d4324b2522571fef6a1466cfeff4997c226b3b4ab3a3ae1dai0",
                fileType: 'svg'
            },
            file: `${process.cwd()}/testImg/1.png`,
            receiveAddress: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h",
            metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz", description: "batch inscription on a specific sat type"},
            size: 472    
        },
        {   
            deligate: {
                id: "8be29549cca88b5ee60ca03ad1e3eba602348295b18a523421a1b08b5eacd858i0",
                fileType: 'html'
            },
            file: `${process.cwd()}/testImg/2.png`,
            receiveAddress: "tb1pk9gg9ywgd3zjpzexsuhzfh5jmfterg8nw8a7h6l4tweuure62hmsxfv8r5",
            metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz", description: "batch inscription on a specific sat type"},
            size: 490    
        }
    ]
}

const options = {   
    deligate: {
        id: "8be29549cca88b5ee60ca03ad1e3eba602348295b18a523421a1b08b5eacd858i0",
        //fileType: 'html'
    },
    service_fee: 1000, 
    service_address: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", 
    collection_fee: 1000, 
    collection_address: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", 
    //metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz", description: "simulating special sat inscription"},
    sat_details: sat_details, 
}

let filePaths = [`${process.cwd()}/testImg/1.png`]
let feeRate = 5
let padding = 550
let publicKey = "a6d20289a0861be945bd0df88aa9500be81717af112c2c1ebfbfbe8012b60ba3"
let privateKey = "84e5fb722756527c075ec5708d65d2b72fa412d4ed6104126a46e304915d2e9f"
let insc_fundAddr = "tb1psjnu8he228hhddeauf5c7jcjhfut6l09kv6uw2cpklvxm4cj49vqvm4ct9"


// getInscriptions({
//     //filePaths: filePaths, 
//     publicKey: publicKey, 
//     networkName: "testnet", 
//     feerate: feeRate, 
//     padding: padding, 
//     options: options,
//     //batch: batchData
// }).then(res => {
//     console.log(res)
// }).catch()

// splitFunds({
//     //filePaths: filePaths, 
//     privateKey: privateKey, 
//     networkName: "testnet", 
//     feerate: feeRate, 
//     padding: padding, 
//     options: options, 
//     //batch: batchData
// }).then(res => {
//     console.log(res)
// }).catch()

// createInscribeTransactions({
//     //filePaths: filePaths, 
//     privateKey:privateKey, 
//     receiveAddress:"tb1pk9gg9ywgd3zjpzexsuhzfh5jmfterg8nw8a7h6l4tweuure62hmsxfv8r5", 
//     networkName:"testnet", 
//     feerate:feeRate, 
//     padding:padding, 
//     options:options, 
//     //batch: batchData
// }).then(res => {
//     console.log(res)
// }).catch()

//console.log(getInitData2({networkName: "testnet", privateKey: privateKey, addressType: "taproot"}))

//console.log(getKeyPair({networkName: "testnet"}))

// console.log("inscription cost 1", getInscriptionCost({
//     //fileSizes: [472], 
//     feerate: feeRate, 
//     padding: 550, 
//     options: options,
//     //batch: batchData
// }))

//console.log(getAllAddress({privateKey: "9c45ef6897c0588477ddf51325ea10203168e06a2ffbc2586c0878364f82012f", networkName: "testnet"}))

//console.log(getDeligateData("7d2f34fec10956e3025a8a02707a7bff9d4eaa841b2baadfedd40e31ce8c1a17i256"))