from eth.constants import (
    EMPTY_UNCLE_HASH,
    DIFFICULTY_ADJUSTMENT_DENOMINATOR,
    DIFFICULTY_MINIMUM,
    BOMB_EXPONENTIAL_PERIOD,
    BOMB_EXPONENTIAL_FREE_PERIODS,
)
from eth.utils.db import (
    get_parent_header,
)
from eth.validation import (
    validate_gt,
    validate_header_params_for_configuration,
)
from eth.vm.forks.frontier.headers import (
    create_frontier_header_from_parent,
)

from .constants import (
    BYZANTIUM_DIFFICULTY_ADJUSTMENT_CUTOFF
)


def compute_ecc_difficulty(parent_header, timestamp):
    """
    https://github.com/ethereum/EIPs/issues/100
    """
    parent_timestamp = parent_header.timestamp
    validate_gt(timestamp, parent_timestamp, title="Header.timestamp")

    parent_difficulty = parent_header.difficulty
    offset = parent_difficulty // DIFFICULTY_ADJUSTMENT_DENOMINATOR

    has_uncles = parent_header.uncles_hash != EMPTY_UNCLE_HASH
    time_diff_level = (timestamp - parent_timestamp) // BYZANTIUM_DIFFICULTY_ADJUSTMENT_CUTOFF
    adj_factor = max(
        (
            (2 if has_uncles else 1) -
            (time_diff_level)
        ),
        -99,
    )
    difficulty = max(
        parent_difficulty + offset * adj_factor,
        min(parent_header.difficulty, DIFFICULTY_MINIMUM)
    )
    num_bomb_periods = (
        max(
            0,
            parent_header.block_number + 1 - 3000000,
        ) // BOMB_EXPONENTIAL_PERIOD
    ) - BOMB_EXPONENTIAL_FREE_PERIODS

    if time_diff_level < -1:
        ecc_diff_level = -1
    else:
        ecc_diff_level = time_diff_level

    if num_bomb_periods >= 0:
        return max(difficulty + 2**num_bomb_periods, DIFFICULTY_MINIMUM), ecc_diff_level
    else:
        return difficulty, ecc_diff_level


def create_byzantium_header_from_parent(parent_header, **header_params):
    if 'difficulty' not in header_params:
        header_params.setdefault('timestamp', parent_header.timestamp + 1)

        header_params['difficulty'] = compute_byzantium_difficulty(
            parent_header=parent_header,
            timestamp=header_params['timestamp'],
        )
    return create_frontier_header_from_parent(parent_header, **header_params)


def configure_byzantium_header(vm, **header_params):
    validate_header_params_for_configuration(header_params)

    with vm.block.header.build_changeset(**header_params) as changeset:
        if 'timestamp' in header_params and changeset.block_number > 0:
            parent_header = get_parent_header(changeset.build_rlp(), vm.chaindb)
            changeset.difficulty = compute_byzantium_difficulty(
                parent_header,
                header_params['timestamp'],
            )

        header = changeset.commit()
    return header
