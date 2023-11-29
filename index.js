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
  genQrCode,
  createInscriptionTransacrion
} from "./bitcoin/utils.js"

const qip_wallet = {
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
  hasInscription,
  getAllUtxo,
  genQrCode,
  createInscriptionTransacrion
}

export default qip_wallet