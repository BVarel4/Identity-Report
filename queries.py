DISCOVERY_QUERY = """
query DiscoverRiskFactorTypes($after: Cursor, $domains: [String!], $first: Int) {
  entities(
    archived: false,
    domains: $domains
    first: $first
    after: $after
  ) {
    nodes {
      entityId
      type
      primaryDisplayName
      secondaryDisplayName
      riskScoreSeverity
      riskFactors {
        __typename
        type
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

DETAIL_QUERY = """
query RiskDetails($after: Cursor, $domains: [String!], $first: Int) {
  entities(
    archived: false,
    domains: $domains
    first: $first
    after: $after
  ) {
    nodes {
      entityId
      type
      primaryDisplayName
      secondaryDisplayName
      riskScoreSeverity
      riskFactors {
        __typename
        type
        ... on AttackPathBasedRiskFactor {
          attackPath {
            entity {
              entityId
              type
              primaryDisplayName
              secondaryDisplayName
              riskScoreSeverity
            }
            relation
            nextEntity {
              entityId
              type
              primaryDisplayName
              secondaryDisplayName
              riskScoreSeverity
            }
          }
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""
