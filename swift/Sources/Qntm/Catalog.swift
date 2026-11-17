import Foundation

extension GatewayRecipe {
  public static func starterCatalog() throws -> [String: GatewayRecipe] {
    guard let url = Bundle.module.url(forResource: "starter", withExtension: "json") else {
      throw QntmError.invalid("Missing starter recipe catalog")
    }
    return try catalog(data: Data(contentsOf: url))
  }
}
