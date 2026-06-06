import ArgumentParser
import SwiftUI

@main
struct Entrypoint {
    static func main() throws {
        var command = try VZM.parseAsRoot()
        
        if var asyncCommand = command as? AsyncParsableCommand {
            if asyncCommand is Run {
                MenuBarAppEnvironment.shared.command = asyncCommand
                VZMMenuBarApp.main()
            } else {
                Task {
                    try await asyncCommand.run()
                }
                RunLoop.main.run()
            }
        } else {
            try command.run()
        }
    }
}
