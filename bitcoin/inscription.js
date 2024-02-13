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
 import {init, getTransactionSize, getUtxo} from './utils.js'
import { error } from "console"
 
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

export const getInitData = ({privateKey, networkName}) => {
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
        }
    }catch(e){
        throw new Error(e.message)
    }
}

const _getInscription = ({files, publicKey, networkName, feerate, padding, options}) => {
    try{
        const ec = new TextEncoder();
        if(!files || !publicKey || !networkName){
            throw new Error ("files, publicKey, and networkName are required to create an inscription. Received: ", files, publicKey, networkName)
        }
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

        if(options && options.metadata){
            const scriptData = createInscriptionScript({pubkey: pubkey, mimetype: mimetype, data: data, metadata: options.metadata})
            script = scriptData.script;
            script_backup = scriptData.script_backup;
        }else{
            const scriptData = createInscriptionScript({pubkey: pubkey, mimetype: mimetype, data: data})
            script = scriptData.script;
            script_backup = scriptData.script_backup;
        }

        const leaf = Tap.encodeScript(script);
        const [tapkey, cblock] = Tap.getPubKey(pubkey, { target: leaf });

        const inscriptionAddress = Address.p2tr.encode(tapkey, addressEncoding);        
        const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txBytes * feerate;

        const txsize = prefix + Math.floor(data.length / 4);
        const fee = feerate * txsize + pad;
        
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

export const getInscriptionCost = ({fileSizes, feerate, padding, options}) => {
    try{
        let pad
        if(!padding || padding < 550){
            pad = 550
        }else{
            pad = padding
        }

        let inputs = 1
        if(options && options.satTx){
            inputs += 2
        }

        let total_fee = 0;

        for (let i = 0; i < fileSizes.length; i++) {
            const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txBytes * feerate;
            const txsize = prefix + Math.floor(fileSizes[i] / 4);
            const fee = feerate * txsize + pad;
            total_fee += fee;
        }
        
        let outputCount = fileSizes.length
        
        let total_fees = total_fee
        if(options && options.service_fee){
            if(!options.service_address){
                throw new Error ("service_address is required to add a service fee")
            }
            const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txBytes * feerate;
            total_fees += options.service_fee * fileSizes.length + prefix
            outputCount += 1
        }
        if(options && options.collection_fee){
            if(!options.collection_address){
                throw new Error ("collection_address is required to add a collection fee")
            }
            const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txBytes * feerate;
            total_fees += options.collection_fee * fileSizes.length + prefix
            outputCount += 1
        }

        let outFeeData = [{outputType: "P2TR", count: outputCount}]
        total_fees += getTransactionSize({input: inputs, output:outFeeData, addressType: "taptoot"}).txBytes * feerate;
        return total_fees

    }catch(e){
        throw new Error(e.message)
    }
}

export const getInscriptions = async ({filePaths, publicKey, networkName, feerate, padding, options}) => {
    try{
        let inscriptions = [];
        let total_fee = 0;
        let files = await getFileData(filePaths)

        let inputs = 1
        if(options && options.satTx){
            if(typeof options.satTx.txid !== "string"){
                throw new Error ("satTx Txid must be a string")
            }
            inputs += 2
        }

        if(files.length > 1 && options && options.satTx){
            throw new Error (`inscription on special sat can only be done on one file, you have ${files.length} files`)
        }

        for (let i = 0; i < files.length; i++) {
            let inscription = _getInscription({files: files[i], publicKey: publicKey, networkName: networkName, feerate: feerate, padding: padding, options: options})
            inscriptions.push(inscription)
            total_fee += inscription.fee
        }

        let outputCount = inscriptions.length
        
        let total_fees = total_fee
        if(options && options.service_fee){
            if(!options.service_address){
                throw new Error ("service_address is required to add a service fee")
            }
            const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txBytes * feerate;
            total_fees += options.service_fee * inscriptions.length + prefix
            outputCount += 1
        }
        if(options && options.collection_fee){
            if(!options.collection_address){
                throw new Error ("collection_address is required to add a collection fee")
            }
            const prefix = getTransactionSize({input:1, output:[{outputType: "P2TR", count: 1}], addressType: "taptoot"}).txBytes * feerate;
            total_fees += options.collection_fee * inscriptions.length + prefix
            outputCount += 1
        }

        let outFeeData = [{outputType: "P2TR", count: outputCount}]
        total_fees += getTransactionSize({input: inputs, output:outFeeData, addressType: "taptoot"}).txBytes * feerate;

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
        throw new Error(e.message)
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

export const splitFunds = async ({filePaths, privateKey, networkName, feerate, padding, options}) => {
    try{
        if(!filePaths || !privateKey || !networkName || !feerate || !padding){
            throw new Error("filePaths, privateKey, networkName, feerate, and padding are required to create an inscription. Received: ", filePaths, privateKey, networkName, feerate, padding)
        }
        let initData = getInitData({privateKey: privateKey, networkName: networkName})
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
        
        let total_fees = inscData.total_fees;
        let inscriptions = inscData.inscriptions;

        let vin = []
        if(options && options.satTx){
            const sat_utxo = await handleSatTx({satTx: options.satTx, networkName: networkName, address: fundingAddress})
            if(!sat_utxo){
                console.log("satTx utxo not found")
                return
            }
            vin.push({
                txid: sat_utxo.txid,
                vout: sat_utxo.vout,
                prevout: {
                    value: sat_utxo.value,
                    scriptPubKey: [ 'OP_1', initData.init_tapkey ]
                },
            })

            outputs.push(
                {
                    value: inscriptions[0].fee + sat_utxo.value,
                    scriptPubKey: [ 'OP_1', inscriptions[0].tapkey ]
                }
            );
            
        }else{
            for (let i = 0; i < inscriptions.length; i++) {
                outputs.push(
                    {
                        value: inscriptions[i].fee,
                        scriptPubKey: [ 'OP_1', inscriptions[i].tapkey ]
                    }
                );
            }
        }

        let utxos = await getUtxo({address: fundingAddress, networkName: networkName})
        
        if(utxos.length === 0){
            throw new Error("No funds available for inscription")
        }
        let spend_utxo 
        utxos.forEach(x => {
            if(x.value >= total_fees){
                spend_utxo = x
            }else{
                throw new Error("Insufficient funds")
            }
        })

        vin.push({
            txid: spend_utxo.txid,
            vout: spend_utxo.vout,
            prevout: {
                value: spend_utxo.value,
                scriptPubKey: [ 'OP_1', initData.init_tapkey ]
            },
        })



        if(options && options.service_fee){
            outputs.push(
                {
                    value: options.service_fee,
                    scriptPubKey: [ 'OP_1', Address.p2tr.decode(options.service_address, getAddressEncoding({networkName: networkName})).hex ]
                }
            );
        }
        if(options && options.collection_fee){
            outputs.push(
                {
                    value: options.collection_fee,
                    scriptPubKey: [ 'OP_1', Address.p2tr.decode(options.collection_address, getAddressEncoding({networkName: networkName})).hex ]
                }
            );
        }

        const init_redeemtx = Tx.create({
            vin  : vin,
            vout : outputs
        })

        //Sign the transaction
        const pubkey = hexToBytes(initData.publicKey)
        init_redeemtx.vin.forEach((x, index) => {
            const init_sig = Signer.taproot.sign(getKeyPair({privateKey:privateKey}).seckey.raw, init_redeemtx, index, {extension: initData.init_leaf});
            x.witness = [ init_sig.hex, [ pubkey, 'OP_CHECKSIG'], initData.init_cblock ]
        })
               
        let rawtx = Tx.encode(init_redeemtx).hex;
        const txid = Tx.util.getTxid(Tx.encode(init_redeemtx))
        return {txHex: rawtx, txid: txid}
    }catch(e){
        throw new Error(e.message)
    }

}

export const createInscribeTransactions = async ({filePaths, privateKey, receiveAddress, networkName, feerate, padding, options}) => {
    try{

        if(!filePaths || !privateKey || !receiveAddress || !networkName || !feerate || !padding){
            throw new Error("filePaths, privateKey, receiveAddress, networkName, feerate, and padding are required to create an inscription. Received: ", filePaths, privateKey, receiveAddress, networkName, feerate, padding)
        }

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
                    vout: i,
                    prevout: {
                        value: spend_utxo.value,
                        scriptPubKey: [ 'OP_1', inscription.tapkey ]
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
    console.log(addressData)
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

// const options = {   
//     service_fee: 1000, 
//     service_address: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", 
//     //collection_fee: 1000, 
//     //collection_address: "tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", 
//     //metadata: {creator: "arch.xyz", collection: "test collection", platform: "inscribable.xyz"},
//     // satTx: {
//     //     txid: "9225058961e6e73273d9b58748dbcd5f832a3f0cebbb88daf424e0c15314ab56",
//     //     vout: 0,
//     //     value: 1000
//     // }
// }
// let filePaths = [`${process.cwd()}/testImg/5.png`]
// let feeRate = 10
// let padding = 550
// let publicKey = "ed1c0fe066cc7853988b633fb842859c3b9697e07703f69b9ad43a5d9dad5d8e"
// let privateKey = "61d89cb96822917abf5d502e671833c884523f533f144ca2c83d6cd83de0ea68"

// getInscriptions({filePaths: filePaths, publicKey: publicKey, networkName: "testnet", feerate: feeRate, padding: padding, options: options }).then(res => {
//     console.log(res)
// }).catch()

// splitFunds({filePaths: filePaths, privateKey: privateKey, networkName: "testnet", feerate: feeRate, padding: padding, options: options}).then(res => {
//     console.log(res)
// }).catch()

// createInscribeTransactions({filePaths:filePaths, privateKey:privateKey, receiveAddress:"tb1pxlsh06u5ej72gjvmcl9ktuq4jw8ja2pzx5jqgypyxzfw0c32j0ysppm29h", networkName:"testnet", feerate:feeRate, padding:padding, options:options}).then(res => {
//     console.log(res)
// }).catch()

//console.log(getInitData({networkName: "testnet", privateKey: privateKey}))
//console.log(getKeyPair({networkName: "testnet"}))

//console.log(getInscriptionCost({fileSizes: [472, 490, 494, 408], feerate: feeRate, padding: 550, options: options}))

