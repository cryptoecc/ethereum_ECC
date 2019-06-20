from datetime import datetime
from eth.chains.base import MiningChain
from eth.vm.forks.petersburg import PetersburgVM
from eth.tools.builder.chain import build, fork_at

from eth.db.atomic import AtomicDB
from eth.consensus.pow import mine_pow_nonce, mine_eccpow_nonce

from eth import constants

GENESIS_PARAMS = {
      'parent_hash': constants.GENESIS_PARENT_HASH,
      'uncles_hash': constants.EMPTY_UNCLE_HASH,
      'coinbase': constants.ZERO_ADDRESS,
      'transaction_root': constants.BLANK_ROOT_HASH,
      'receipt_root': constants.BLANK_ROOT_HASH,
      'difficulty': 1,
      'block_number': 0,#constants.GENESIS_BLOCK_NUMBER,
      'gas_limit': 3141592,
      'timestamp': int(datetime.now().timestamp()), # get current time
      'extra_data': constants.GENESIS_EXTRA_DATA,
      'nonce': constants.GENESIS_NONCE
  }


# There is two ways to make custom chain class
# Below This alternative way
# chain_class = MainnetChain.configure(
#     __name__='Test Chain',
#     vm_configuration=(
#         (constants.GENESIS_BLOCK_NUMBER, ByzantiumVM),
#     ),
# )
chain_class = build(MiningChain, fork_at(PetersburgVM, 0))

# initialize a fresh chain
chain = chain_class.from_genesis(AtomicDB(), GENESIS_PARAMS)

for i in range(3):
    # print("Parents header hash : ", chain.header.parent_hash.hex())
    current_block = chain.get_block()
    print("block timestamp : " , chain.header.timestamp)
    block = chain.get_vm().finalize_block(chain.get_block())
    nonce, mix_hash = mine_pow_nonce(block.number,
                                     block.header.mining_hash,
                                     block.header.difficulty)

    # TODO : adjust difficulty level by block mined interval

    # nonce, mined_hash = mine_eccpow_nonce(1,
    #                                       block.header.mining_hash,
    #                                       chain.header.parent_hash)

    block = chain.mine_block(mix_hash=mix_hash, nonce=nonce)
    print("mined block : {}".format(block.number), block.hash.hex(), block.header.difficulty)
