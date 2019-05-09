const RocksDb = require('../../../sbmtjs/src/storage/rocksdb');
const MerkleTree = require('../../../sbmtjs/src/tree');
const Mimc7Hasher = require('../../../sbmtjs/src/hasher/mimc7');

const Web3 = require('web3');
const SemaphoreABI = require('../../build/contracts/Semaphore.json');

const snarkjs = require('snarkjs');
const bigInt = snarkjs.bigInt;

const crypto = require('crypto');
const winston = require('winston');

const transaction_confirmation_blocks = parseInt(process.env.TRANSACTION_CONFIRMATION_BLOCKS) || 24;

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL,
    format: winston.format.json(),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )

        })
    ]
});

function timeout(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

const last_block_key = 'last_block';
const state_block_key_prefix = 'state_block';
const signal_index_key = 'signal_index';
const signal_key_prefix = 'signal';

beBuff2int = function(buff) {
    let res = bigInt.zero;
    for (let i=0; i<buff.length; i++) {
        const n = bigInt(buff[buff.length - i - 1]);
        res = res.add(n.shl(i*8));
    }
    return res;
};

beInt2Buff = function(n, len) {
    let r = n;
    let o =0;
    const buff = Buffer.alloc(len);
    while ((r.greater(bigInt.zero))&&(o<buff.length)) {
        let c = Number(r.and(bigInt("255")));
        buff[buff.length - o - 1] = c;
        o++;
        r = r.shr(8);
    }
    if (r.greater(bigInt.zero)) throw new Error("Number does not feed in buffer");
    return buff;
};

class SemaphoreServer {

    constructor(storage, node_url, contract_address, tree) {
        this.storage = storage;
        this.web3 = new Web3(new Web3.providers.HttpProvider(node_url));
        this.web3.eth.transactionConfirmationBlocks = transaction_confirmation_blocks;
        logger.verbose(`transaction confirmation blocks: ${this.web3.eth.transactionConfirmationBlocks}`);
        this.contract_address = contract_address;
        this.tree = tree;
        this.contract = new this.web3.eth.Contract(
            SemaphoreABI.abi, 
            this.contract_address,
        );
    }

    async event_processing_loop() {
        while (true) {
            const last_processed_block = await this.get_last_processed_block();
            const current_block_number = await this.web3.eth.getBlockNumber();

            logger.debug(`last_processed_block: ${last_processed_block}`);
            logger.debug(`current_block_number: ${current_block_number}`);

            const code = await this.web3.eth.getCode(this.contract_address, last_processed_block);
            if ( code == '0x') {
                await this.storage.put(last_block_key, (last_processed_block + 1).toString());
                continue;
            }

            const state_root = await this.contract.methods.root().call({from: from_address}, last_processed_block);
            const state_signal_rolling_hash = await this.contract.methods.signal_rolling_hash().call({from: from_address}, last_processed_block);
            logger.debug(`state_root: ${state_root}, state_signal_rolling_hash: ${state_signal_rolling_hash}`);

            const saved_state_block = await this.get_state_for_block(last_processed_block);
            logger.debug(`saved_state_block: ${JSON.stringify(saved_state_block)}`);

            if ( saved_state_block.root && (state_root != saved_state_block.root || 
                state_signal_rolling_hash != saved_state_block.signal_rolling_hash)) {
                await this.rollback_one_step(last_processed_block);
                continue;
            }

            const target_block_number = Math.min(current_block_number, last_processed_block + 10);

            const logs = await this.contract.getPastEvents('allEvents', {
                fromBlock: last_processed_block + 1,
                toBlock: target_block_number,
                address: this.contract_address,
            });
            await this.save_events(
                logs, 
                state_signal_rolling_hash,
                target_block_number
            );

            if (logs.length > 0) {
                const state_root = await this.contract.methods.root().call({from: from_address}, last_processed_block);
                const state_signal_rolling_hash = await this.contract.methods.signal_rolling_hash().call({from: from_address}, last_processed_block);
                logger.verbose(`state_root: ${state_root}, state_signal_rolling_hash: ${state_signal_rolling_hash}`);

                const saved_state_block = await this.get_state_for_block(last_processed_block);
                logger.verbose(`saved_state_block: ${JSON.stringify(saved_state_block)}`);
            }

            if (target_block_number == current_block_number) {
                await timeout(5000);
            }
        }
    }

    async rollback_one_step(current_block) {
        while (true) {
            if (current_block < 0) {
                throw new Error('cannot roll back to a negative block');
            }
            const state_for_block = this.get_state_for_block(current_block--);
            if (state_for_block.root) {
                await this.tree.rollback_to_root(state_for_block.root);
                await this.rollback_signals_to_rolling_hash(state_for_block.signal_rolling_hash);

                await this.storage.put(last_block_key, current_block.toString());

                break;
            }
        }
    }


    async get_state_for_block(block_number) {
        return JSON.parse(await this.storage.get_or_element(`${state_block_key_prefix}_${block_number}`, '{}'));
    }

    async prepare_save_state_for_block(block_number, data) {
        return {
            key: `${state_block_key_prefix}_${block_number}`,
            value: JSON.stringify(data),
        }
    }

    async save_events(events, rolling_hash, block_number) {
        rolling_hash = bigInt(rolling_hash);

        let key_values = [];
        for (let i = 0; i < events.length; i++) {
            const event = events[i];

            logger.info(`got event ${event.event} with values ${JSON.stringify(event.returnValues)}`);
            if (event.event == 'LeafAdded') {
                await tree.update(event.returnValues.leaf_index, event.returnValues.leaf.toString());
            } else if (event.event == 'LeafUpdated') {
                await tree.update(event.returnValues.leaf_index, event.returnValues.leaf.toString());
            } else if (event.event == 'SignalBroadcast') {
                rolling_hash = beBuff2int(
                    crypto.createHash('sha256').update(beInt2Buff(rolling_hash, 32)).update(
                        ('00' + crypto.createHash('sha256').update(event.returnValues.signal.slice(2), 'hex').digest().slice(0,31).toString('hex')), 'hex'
                    ).digest()
                );
                const adds = await this.prepare_signal_add(
                    event.returnValues.signal,
                    event.returnValues.nullifiers_hash,
                    block_number,
                    rolling_hash.toString(),
                );
                key_values.push(adds[0]);
                key_values.push(adds[1]);
            } else {
                logger.error(`Unknown event: ${JSON.stringify(event)}`);
            }
        }

        key_values.push({ key: last_block_key, value: block_number.toString()});
        const root = await tree.root();
        key_values.push(await this.prepare_save_state_for_block(block_number, {
            root,
            signal_rolling_hash: rolling_hash.toString(),
        }));
        await this.storage.put_batch(key_values);
    }

    async get_last_processed_block() {
        return parseInt(await this.storage.get_or_element(last_block_key, '0'));
    }

    async prepare_signal_add(signal, nullifiers_hash, block_number, rolling_hash) {
        let current_index = parseInt(await this.storage.get_or_element(signal_index_key, '0'));
        current_index++;

        const signal_key = `${signal_key_prefix}_${current_index}`;
        return [{
            key: signal_key,
            value: JSON.stringify({
                signal,
                nullifiers_hash,
                block_number,
                rolling_hash,
            }),
        }, {
            key: signal_index_key,
            value: current_index,
        }];
    }

    async rollback_signals_to_rolling_hash(rolling_hash) {
        while (true) {
            let current_index = parseInt(await this.storage.get_or_element(signal_index_key, '0'));
            current_index--;
            const signal_key = `${signal_key_prefix}_${current_index}`;
            const signal_data = await this.storage.get(signal_key);
            if (signal_data.rolling_hash == rolling_hash) {
                break;
            } else {
                await this.storage.put(signal_index_key, current_index);
                await this.storage.del(signal_key);
            }
        }
    }
}

const prefix = 'semaphore';
const storage = new RocksDb(process.env.DB_PATH || 'semaphore_server.db');
const hasher = new Mimc7Hasher();
const default_value = '0';

const tree = new MerkleTree(
    prefix,
    storage,
    hasher,
    4,
    default_value,
);

const semaphore = new SemaphoreServer(
    storage,
    process.env.NODE_URL,
    process.env.CONTRACT_ADDRESS,
    tree,
);

semaphore.event_processing_loop()
.catch((err) => logger.error(err));

const express = require('express');
var bodyParser = require('body-parser')

const app = express();
app.use(bodyParser.json());
const port = process.env.SEMAPHORE_PORT;

app.get('/path/:index', async (req, res) => {
    const leaf_index = req.params.index;
    const path = await semaphore.tree.path(parseInt(leaf_index));
    res.send(path);
});

app.get('/path_for_element/:element', async (req, res) => {
    const leaf = req.params.element;
    const leaf_index = await semaphore.tree.element_index(leaf);
    if (leaf_index < 0) {
        res.status(400).send({ error: `Element ${leaf} not found` });
        return;
    }
    const path = await semaphore.tree.path(leaf_index);
    res.send(path);
});

app.get('/element_index/:element', async (req, res) => {
    const leaf = req.params.element;
    const leaf_index = await semaphore.tree.element_index(leaf);
    if (leaf_index < 0) {
        res.status(400).send({ error: `Element ${leaf} not found` });
        return;
    }
    res.send({ index: leaf_index });
});



app.get('/signals/:start_index/:amount/:order', async (req, res) => {
    const amount = parseInt(req.params.amount)
    if (isNaN(amount)) {
        res.status(400).send({ error: `Invalid amount ${amount}`});
        return;
    }
    const order = req.params.order;
    const start_index = parseInt(req.params.start_index)
    if (isNaN(start_index)) {
        res.status(400).send({ error: `Invalid start index ${start_index}`});
        return;
    }

    let signals = [];

    if (order == 'asc') {
        for (let i = 0; i < amount; i++) {
            const signal_key = `${signal_key_prefix}_${start_index + i}`;
            const signal_data = JSON.parse(await semaphore.storage.get_or_element(signal_key, '{}'));
            if (signal_data.signal) {
                signals.push(signal_data);
            }
        }
    } else if (order == 'desc') {
        const latest_signal_index = await semaphore.storage.get_or_element(signal_index_key, 0);
        for (let i = 0; i < amount; i++) {
            const signal_key = `${signal_key_prefix}_${latest_signal_index - start_index - i}`;
            const signal_data = JSON.parse(await semaphore.storage.get_or_element(signal_key, '{}'));
            if (signal_data.signal) {
                signals.push(signal_data);
            }
        }
    } else {
        res.status(400).send({error:  `Unknown order ${order}`});
        return;
    }

    res.send(signals);
});

const check_login = (req) => {
    return (req.header('login') == process.env.SEMAPHORE_LOGIN);
};

const from_address = process.env.FROM_ADDRESS;
const from_private_key = process.env.FROM_PRIVATE_KEY;
const chain_id = parseInt(process.env.CHAIN_ID);

app.post('/add_identity', async (req, res) => {
    if (check_login) {
        const leaf = req.body.leaf;
        const encoded = await semaphore.contract.methods.insertIdentity(leaf).encodeABI();
        //logger.verbose('encoded: ' + encoded);
        const gas_price = '0x' + (await semaphore.web3.eth.getGasPrice()).toString(16);
        //logger.verbose('gas_price: ' + gas_price);
        const gas = '0x' + (await semaphore.web3.eth.estimateGas({
            from: from_address,
            to: semaphore.contract_address,
            data: encoded
        })).toString(16);
        //logger.verbose('gas: ' + gas);
        const nonce = await semaphore.web3.eth.getTransactionCount(from_address);
        logger.verbose('nonce: ' + nonce);
        logger.verbose('chain_id: ' + chain_id);
        const tx_object = {
            gas: gas,
            gasPrice: gas_price,
            from: from_address,
            to: semaphore.contract_address,
            data: encoded,
            chainId: chain_id,
            nonce: nonce,
        };
        logger.verbose(`tx_object: ${JSON.stringify(tx_object)}`);
        logger.verbose('signing tx');
        const signed_tx = await semaphore.web3.eth.accounts.signTransaction(tx_object, from_private_key);
        logger.info(`sending tx: ${signed_tx.messageHash}`);

        semaphore.web3.eth.sendSignedTransaction(signed_tx.rawTransaction)
        .on('receipt', () => {
            logger.verbose(`tx sent: ${signed_tx.messageHash}`);
        })
        .catch((err) => logger.error(`tx send error: ${JSON.stringify(err)}`));

        res.json({});
    } else {
        res.status(400).json({error: 'Invalid login'});
    }
});

process.on('unhandledRejection', function(err, promise) {
    logger.error(err.message);
    process.exit(1);
});

process.on('uncaughtException', function(err) {
    logger.error(err.message);
    process.exit(1);
});

app.listen(port, () => logger.verbose(`Semaphore running on port ${port}.`))