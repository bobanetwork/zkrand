import {Wallet, providers} from 'ethers'
import {Bcfg} from '@eth-optimism/core-utils'
import * as dotenv from 'dotenv'
import Config from 'bcfg'

/* Imports: Core */
import {NodeZkRandService} from '../node'

dotenv.config()

const main = async () => {
    const config: Bcfg = new Config('zkRand')
    config.load({
        env: true,
        argv: true,
    })

    const env = process.env
    const L2_NODE_WEB3_URL = config.str('l2-node-web3-url', env.L2_NODE_WEB3_URL)
    const NODE_PRIVATE_KEY = config.str('node-private-key', env.NODE_PRIVATE_KEY)

    // Optional
    const POLLING_INTERVAL = config.uint(
        'polling-interval',
        parseInt(env.POLLING_INTERVAL, 10) || 1000 * 12
    )

    const ZK_RAND_ADDRESS = config.str('zk-rand-address', env.ZK_RAND_ADDRESS)

    if (!L2_NODE_WEB3_URL) {
        throw new Error('Must pass L2_NODE_WEB3_URL')
    }

    const l2Provider = new providers.StaticJsonRpcProvider(L2_NODE_WEB3_URL)

    let wallet: Wallet
    wallet = new Wallet(NODE_PRIVATE_KEY, l2Provider)

    const chainId = (await l2Provider.getNetwork()).chainId

    const service = new NodeZkRandService({
        l2RpcProvider: l2Provider,
        l2Wallet: wallet,
        chainId,
        zkRandAddress: ZK_RAND_ADDRESS,
        pollingInterval: POLLING_INTERVAL,
    })

    await service.start()
}

if (require.main === module) {
    main()
}

export default main
