package ray.eldath.portableseal.scala.test

import io.grpc.ManagedChannelBuilder
import org.scalatest.BeforeAndAfterEach
import org.scalatest.flatspec._
import org.scalatest.matchers.should.Matchers._
import org.scalatest.prop.TableDrivenPropertyChecks
import ray.eldath.portableseal.context.ContextParameters.PlainModulus.PlainModulusNumber
import ray.eldath.portableseal.context.DecryptionNecessity.Ciphertext.SerializedCiphertext
import ray.eldath.portableseal.context.DecryptionNecessity.SecretKey
import ray.eldath.portableseal.context.EncryptionNecessity.Plaintext
import ray.eldath.portableseal.context.EncryptionNecessity.PublicKey.PublicKeyBytes
import ray.eldath.portableseal.context.{BfvContextGrpc, ContextParameters, DecryptionNecessity, EncryptionNecessity}
import ray.eldath.portableseal.evaluator.BinaryOperand.Operand.CiphertextId
import ray.eldath.portableseal.evaluator.{BinaryOperand, EvaluatorGrpc}
import ray.eldath.portableseal.switcher.EvaluatorSwitcherGrpc
import ray.eldath.portableseal.transmission.PlaintextData
import ray.eldath.portableseal.util.Nothing

import scala.language.postfixOps

class PolynomialTest extends AnyFlatSpec with BeforeAndAfterEach with TableDrivenPropertyChecks {
  private val channel = ManagedChannelBuilder.forTarget(Option(System.getenv("PORTABLESEAL_SERVICE_TARGET")).getOrElse("localhost:5000")).usePlaintext().asInstanceOf[ManagedChannelBuilder[_]].build

  private val context = BfvContextGrpc.blockingStub(channel)
  private val evaluator = EvaluatorGrpc.blockingStub(channel)
  private val switcher = EvaluatorSwitcherGrpc.blockingStub(channel)
  private lazy val keyPair = context.keyGen(nothing)

  "Computation of the deep polynomial x^2 + 3 * (x - 2) + 4" should "evict correct result" in {
    forAll(Table("x", 0, 1, -1, Short.MinValue, Short.MaxValue)) { x =>
      context.create {
        ContextParameters(plainModulus = PlainModulusNumber(512), polyModulusDegree = 2048)
      }

      val expected = x * x + 3 * (x - 2) + 4
      printf("%d^2 + 3 * (%d - 2) + 4: should be %d\n", x, x, expected)
      val ct = context.encrypt(x encrypted)

      switcher.constructNew(ct)
      evaluator.square(nothing)
      current("squared 0")

      switcher.constructNew(ct)
      evaluator.sub(2 asOperand)
      evaluator.multiply(3 asOperand)
      evaluator.add(4 asOperand)
      current("computed 1")

      val ct2 = evaluator.getId(nothing)
      switcher.previous(nothing)
      evaluator.add(BinaryOperand(operand = CiphertextId(ct2)))

      current("result") shouldEqual expected

      switcher.clear(nothing)
    }
  }

  private implicit val nothing: Nothing = Nothing.defaultInstance

  implicit class NumberHelper(n: Int) {
    def encrypted: EncryptionNecessity = EncryptionNecessity(plaintext = Plaintext.PlaintextData(PlaintextData(n)), publicKey = PublicKeyBytes(keyPair.publicKey))

    def asOperand: BinaryOperand = BinaryOperand(BinaryOperand.Operand.PlaintextData(PlaintextData(n)))
  }

  def current(header: String = ""): Long = {
    val pt = context.decrypt {
      DecryptionNecessity(ciphertext = SerializedCiphertext(evaluator.current(nothing)),
        secretKey = SecretKey.SecretKeyBytes(keyPair.secretKey))
    }

    val result = pt.plaintext.get.data
    println(s"[$header] data: $result")
    println(s"noiseBudget: ${pt.noiseBudget}")

    result
  }
}

