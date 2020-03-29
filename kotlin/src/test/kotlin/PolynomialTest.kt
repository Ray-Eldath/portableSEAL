import com.google.common.base.Stopwatch
import io.grpc.ManagedChannelBuilder
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.extension.ExtensionContext
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.ArgumentsProvider
import org.junit.jupiter.params.provider.ArgumentsSource
import ray.eldath.portableseal.BfvContextCoroutineGrpc
import ray.eldath.portableseal.EvaluatorCoroutineGrpc
import ray.eldath.portableseal.EvaluatorSwitcherCoroutineGrpc
import ray.eldath.portableseal.Transmission
import java.util.concurrent.TimeUnit
import java.util.stream.Stream
import kotlin.random.Random

class PolynomialTest {
    private val channel = (System.getenv("PORTABLESEAL_SERVICE_TARGET") ?: "localhost:5000").run(::channelForTarget)

    private val context = BfvContextCoroutineGrpc.newStub(channel)
    private val evaluator = EvaluatorCoroutineGrpc.newStub(channel)
    private val switcher = EvaluatorSwitcherCoroutineGrpc.newStub(channel)

    private lateinit var keyPair: Transmission.KeyPair

    @ParameterizedTest
    @ArgumentsSource(SafeLongProvider::class)
    fun evaluate(l: Long): Unit = runBlocking {
        val expected = l * l + 3 * (l - 2) + 4
        println("%d^2 + 3 * (%d - 2) + 4: should be %d".format(l, l, expected))

        val sw = Stopwatch.createStarted()

        val ct = context.encrypt {
            publicKeyId = keyPair.id
            plaintextData = plaintext(l)
        }
        println("${sw.elapsedString()}encrypted")

        switcher.constructNew(ct)
        evaluator.square() // part: x^2 || on 0
        evaluatorCurrentPlain(header = "squared 0", sw = sw)

        switcher.constructNew(ct) // 1
        evaluatorCurrentPlain(false, header = "origin 1")

        evaluator.sub { plaintextData = plaintext(2) }
        evaluator.multiply { plaintextData = plaintext(3) }
        evaluator.add { plaintextData = plaintext(4) } // part: 3 * (x - 2) + 4 || on 1
        evaluatorCurrentPlain(header = "computed 1", sw = sw)

        val p2 = evaluator.getId()
        switcher.previous()
        evaluator.add { ciphertextId = p2 }

        sw.stop()

        assertEquals(expected, evaluatorCurrentPlain(header = "result", sw = sw))
    }.ignore()

    @BeforeEach
    fun beforeTest() = runBlocking {
        context.create {
            plainModulusNumber = 512
            polyModulusDegree = 2048
        }

        keyPair = context.keyGen()
        println("created")
    }

    @AfterEach
    fun clear() = runBlocking {
        switcher.clear()
        println("cleared\n")
    }


    private fun plaintext(data: Long) = Transmission.PlaintextData.newBuilder().setData(data).build()

    private suspend fun evaluatorCurrentPlain(
        showNoiseBudget: Boolean = true,
        showPlainData: Boolean = true,
        header: String = "",
        sw: Stopwatch? = null
    ): Long {
        val ct = evaluator.current()

        val pt = context.decrypt {
            secretKeyId = keyPair.id
            ciphertextId = context.parseCiphertext(ct)
        }
        val r = pt.plaintext.data
        if (sw != null)
            print(sw.elapsedString())

        if (header.isNotEmpty())
            print("$header: ")
        if (showPlainData)
            println("EvaluatorCurrentPlain: $r")
        if (showNoiseBudget)
            println("plaintext noise budget: ${pt.noiseBudget}")

        return r
    }

    private fun channelForTarget(target: String) = ManagedChannelBuilder.forTarget(target).usePlaintext().build()
}

fun <T> T.ignore() {}
fun Stopwatch.elapsedString() = "[%-3dms] ".format(this.elapsed(TimeUnit.MILLISECONDS))

class SafeLongProvider : ArgumentsProvider {
    private val randomGen = Random(System.currentTimeMillis())

    private val random
        get() = randomGen.nextInt().toLong()

    override fun provideArguments(context: ExtensionContext?): Stream<Arguments> =
        Stream.of(
            0L,
            Int.MAX_VALUE.toLong(),
            Int.MIN_VALUE.toLong(),
            random, random
        ).map { Arguments.of(it) }
}