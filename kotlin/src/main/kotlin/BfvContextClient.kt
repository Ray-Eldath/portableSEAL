import io.grpc.ManagedChannel
import io.grpc.ManagedChannelBuilder
import kotlinx.coroutines.runBlocking
import ray.eldath.portableseal.BfvContextCoroutineGrpc
import ray.eldath.portableseal.EvaluatorCoroutineGrpc
import ray.eldath.portableseal.Transmission

object BfvContextClient {
    private val targetService = System.getenv("PORTABLESEAL_SERVICE_TARGET") ?: "localhost:5001"
    private val contextStub = BfvContextCoroutineGrpc.newStub(channelForTarget(targetService))
    private val evaluatorStub = EvaluatorCoroutineGrpc.newStub(channelForTarget(targetService))

    private lateinit var keyPair: Transmission.KeyPair

    @JvmStatic
    fun main(args: Array<String>) {
//        runBlocking {
//            contextStub.create(
//                Context.ContextParameters.newBuilder().setPlainModulusNumber(512).setPolyModulusDegree(2048).build()
//            )
//        }
        runBlocking {
            contextStub.create {
                plainModulusNumber = 512
                polyModulusDegree = 2048
            }.let { println(it) }

            keyPair = contextStub.keyGen()

            contextStub.encrypt {
                plaintextDataBuilder.setData(12345).build()
                publicKeyBytes = keyPair.publicKey
            }.let { evaluatorStub.construct(it) }

            evaluatorStub.add { plaintextDataBuilder.setData(12345).build() }

            evaluatorStub.current().let {
                contextStub.decrypt {
                    serializedCiphertext = it
                    secretKeyBytes = keyPair.secretKey
                }.let { r -> println(r.allFields) }
            }
        }
    }

    private fun channelForTarget(target: String): ManagedChannel =
        ManagedChannelBuilder
            .forTarget(target)
            .usePlaintext()
            .build()
}