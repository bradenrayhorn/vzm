import Foundation

enum TemporaryApprovalDuration: CaseIterable, Identifiable {
    case oneMinute
    case fiveMinutes
    case tenMinutes
    case thirtyMinutes
    case oneHour
    case eightHours

    var id: Self { self }

    var seconds: TimeInterval {
        switch self {
        case .oneMinute: 60
        case .fiveMinutes: 5 * 60
        case .tenMinutes: 10 * 60
        case .thirtyMinutes: 30 * 60
        case .oneHour: 60 * 60
        case .eightHours: 8 * 60 * 60
        }
    }

    var label: String {
        switch self {
        case .oneMinute: "1 minute"
        case .fiveMinutes: "5 minutes"
        case .tenMinutes: "10 minutes"
        case .thirtyMinutes: "30 minutes"
        case .oneHour: "1 hour"
        case .eightHours: "8 hours"
        }
    }
}
