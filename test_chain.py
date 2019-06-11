from datetime import datetime
from eth.chains.base import MiningChain
from eth.vm.forks.byzantium import ByzantiumVM

from eth.db.atomic import AtomicDB
from eth.consensus.pow import mine_pow_nonce

from eth import constants

GENESIS_PARAMS = {
      'parent_hash': constants.GENESIS_PARENT_HASH,
      'uncles_hash': constants.EMPTY_UNCLE_HASH,
      'coinbase': constants.ZERO_ADDRESS,
      'transaction_root': constants.BLANK_ROOT_HASH,
      'receipt_root': constants.BLANK_ROOT_HASH,
      'difficulty': 10,
      'block_number': constants.GENESIS_BLOCK_NUMBER,
      'gas_limit': 3141592,
      'timestamp': int(datetime.now().timestamp()),
      'extra_data': constants.GENESIS_EXTRA_DATA,
      'nonce': constants.GENESIS_NONCE
  }

chain_class = MiningChain.configure(
    __name__='Test Chain',
    vm_configuration=(
        (constants.GENESIS_BLOCK_NUMBER, ByzantiumVM),
    ),
)


# initialize a fresh chain
chain = chain_class.from_genesis(AtomicDB(), GENESIS_PARAMS)

for i in range(10):
    block = chain.get_vm().finalize_block(chain.get_block())

    nonce, mix_hash = mine_pow_nonce(block.number,
                                     block.header.mining_hash,
                                     block.header.difficulty)

    block = chain.mine_block(mix_hash=mix_hash, nonce=nonce)

    print("block : {}".format(block.number), block.header.mining_hash.hex(), block.header.difficulty)
