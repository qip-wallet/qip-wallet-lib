import {
  createAddress, 
  createPassPhrase, 
  createTransaction2,
  createTransaction, 
  getAddressType ,
  getFeeRate ,
  getUtxo, 
  getTransactionDetails, 
  getInputData, 
  signTransaction, 
  signTransaction2,
  getTransactionSize, 
  accountKeys, 
  getAllAddress, 
  hasInscription ,
  getAllUtxo,
  genQrCode,
  createInscriptionTransacrion
} from "./bitcoin/utils.js"

import {
  covertJsonToCbor,
  getAddressEncoding,
  getInscriptions,
  getKeyPair,
  getInitData,
  splitFunds,
  createInscribeTransactions,
  getInscriptionCost
} from "./bitcoin/inscription.js"

const qip_wallet = {
  createAddress, 
  createPassPhrase,  
  createTransaction, 
  createTransaction2,
  signTransaction2,
  getAddressType ,
  getFeeRate ,
  getUtxo, 
  getTransactionDetails, 
  getInputData, 
  signTransaction, 
  getTransactionSize, 
  accountKeys, 
  getAllAddress, 
  hasInscription,
  getAllUtxo,
  genQrCode,
  createInscriptionTransacrion,
}

const inscription = {
  covertJsonToCbor,
  getAddressEncoding,
  getInscriptions,
  getKeyPair,
  getInitData,
  splitFunds,
  createInscribeTransactions,
  getInscriptionCost
}

export {qip_wallet, inscription}