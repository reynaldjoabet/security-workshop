package workshop

object Hello extends Greeting {
  def main(args: Array[String]) = println(greeting)
}

trait Greeting {
  lazy val greeting: String = "hello"
}

opaque type UserId = String
object UserId {

  def apply(id: String): UserId                = id
  extension (userId: UserId) def value: String = userId

}
