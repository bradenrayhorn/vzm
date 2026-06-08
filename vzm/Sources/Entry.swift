import ArgumentParser
import SwiftUI

@main
struct Entrypoint {
    static func main() {
        do {
            var command = try VZM.parseAsRoot()

            if var asyncCommand = command as? AsyncParsableCommand {
                if asyncCommand is Run {
                    MenuBarAppEnvironment.shared.command = asyncCommand
                    VZMMenuBarApp.main()
                } else {
                    Task {
                        do {
                            try await asyncCommand.run()
                            Foundation.exit(EXIT_SUCCESS)
                        } catch {
                            VZM.exit(withError: error)
                        }
                    }
                    RunLoop.main.run()
                }
            } else {
                try command.run()
                Foundation.exit(EXIT_SUCCESS)
            }
        } catch {
            VZM.exit(withError: error)
        }
    }
}
