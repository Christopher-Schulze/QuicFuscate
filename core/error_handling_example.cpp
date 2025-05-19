#include "error_handling.hpp"
#include <iostream>
#include <string>
#include <vector>

namespace quicsand {

// Beispielfunktion, die einen Result-Typ zurückgibt
Result<int> divide(int a, int b) {
    if (b == 0) {
        // Einfache Fehlerrückgabe mit MAKE_ERROR-Makro
        return MAKE_ERROR(
            ErrorCategory::RUNTIME, 
            ErrorCode::INVALID_ARGUMENT, 
            "Division durch Null"
        );
    }
    
    return a / b; // Erfolgsfall: Rückgabe des Ergebnisses
}

// Funktion mit void-Rückgabewert
Result<void> print_positive_number(int n) {
    if (n <= 0) {
        return MAKE_ERROR(
            ErrorCategory::RUNTIME, 
            ErrorCode::INVALID_ARGUMENT, 
            "Zahl muss positiv sein"
        );
    }
    
    std::cout << "Positive Zahl: " << n << std::endl;
    return success(); // Explicit success für void-Result
}

// Eine komplexere Funktion, die andere Result-Funktionen verwendet
Result<double> calculate_average(const std::vector<int>& numbers) {
    if (numbers.empty()) {
        return MAKE_ERROR(
            ErrorCategory::RUNTIME, 
            ErrorCode::INVALID_ARGUMENT, 
            "Liste darf nicht leer sein"
        );
    }
    
    int sum = 0;
    for (int num : numbers) {
        sum += num;
    }
    
    // Division mit Error-Handling
    return divide(sum, static_cast<int>(numbers.size()))
        .map([](int result) {
            return static_cast<double>(result);
        });
}

// Funktion, die Result-Verkettung nutzt
Result<std::string> process_calculation(const std::vector<int>& numbers) {
    return calculate_average(numbers)
        .and_then([](double avg) -> Result<std::string> {
            // Verarbeite das Ergebnis weiter
            if (avg > 100) {
                return MAKE_ERROR(
                    ErrorCategory::RUNTIME,
                    ErrorCode::OPERATION_FAILED,
                    "Durchschnitt zu hoch"
                );
            }
            
            return "Der Durchschnitt beträgt " + std::to_string(avg);
        });
}

// Demo-Funktion, die das Error-Reporting-System nutzt
void demonstrate_error_reporting() {
    // Registriere einen Callback für Runtime-Fehler
    ErrorManager::instance().add_callback(
        ErrorCategory::RUNTIME,
        [](const ErrorInfo& error) {
            std::cout << "Runtime-Fehler aufgetreten: " << error.to_string() << std::endl;
        }
    );
    
    // Registriere einen Callback für einen spezifischen Fehlercode
    ErrorManager::instance().add_callback(
        ErrorCode::INVALID_ARGUMENT,
        [](const ErrorInfo& error) {
            std::cout << "Ungültiges Argument: " << error.message << std::endl;
        }
    );
    
    // Melde einige Fehler
    REPORT_ERROR(
        ErrorCategory::NETWORK,
        ErrorCode::CONNECTION_FAILED,
        "Verbindung zu 192.168.1.1 fehlgeschlagen"
    );
    
    REPORT_ERROR(
        ErrorCategory::RUNTIME,
        ErrorCode::INVALID_ARGUMENT,
        "Ungültiger Parameter: timeout < 0"
    );
    
    // Fehler mit Verbindungs-ID
    REPORT_ERROR(
        ErrorCategory::PROTOCOL,
        ErrorCode::STREAM_ERROR,
        "Stream geschlossen vor Empfang aller Daten",
        12345,  // connection_id
        789     // stream_id
    );
    
    // Zeige Fehlerstatistiken
    auto category_counts = ErrorManager::instance().get_category_counts();
    auto code_counts = ErrorManager::instance().get_code_counts();
    
    std::cout << "\nFehlerstatistiken nach Kategorie:" << std::endl;
    for (const auto& [category, count] : category_counts) {
        std::cout << ErrorInfo::category_to_string(category) << ": " << count << std::endl;
    }
    
    std::cout << "\nFehlerstatistiken nach Code:" << std::endl;
    for (const auto& [code, count] : code_counts) {
        std::cout << ErrorInfo::code_to_string(code) << ": " << count << std::endl;
    }
}

// Hauptfunktion zum Testen des Error-Handling-Systems
void run_error_handling_demo() {
    std::cout << "\n=== Error Handling Demo ===\n" << std::endl;
    
    // Beispiel 1: Einfache Division mit Fehlerbehandlung
    std::cout << "Beispiel 1: Division mit Fehlerbehandlung" << std::endl;
    
    auto result1 = divide(10, 2);
    if (result1) {
        std::cout << "10 / 2 = " << result1.value() << std::endl;
    } else {
        std::cout << "Fehler: " << result1.error().to_string() << std::endl;
    }
    
    auto result2 = divide(10, 0);
    if (result2) {
        std::cout << "10 / 0 = " << result2.value() << std::endl;
    } else {
        std::cout << "Fehler: " << result2.error().to_string() << std::endl;
    }
    
    // Beispiel 2: Void-Rückgabetyp
    std::cout << "\nBeispiel 2: Void-Rückgabetyp" << std::endl;
    
    auto print_result1 = print_positive_number(5);
    if (!print_result1) {
        std::cout << "Fehler: " << print_result1.error().to_string() << std::endl;
    }
    
    auto print_result2 = print_positive_number(-3);
    if (!print_result2) {
        std::cout << "Fehler: " << print_result2.error().to_string() << std::endl;
    }
    
    // Beispiel 3: Komplexere Verkettung
    std::cout << "\nBeispiel 3: Komplexere Verkettung" << std::endl;
    
    std::vector<int> numbers1 = {10, 20, 30, 40};
    auto proc_result1 = process_calculation(numbers1);
    if (proc_result1) {
        std::cout << "Ergebnis: " << proc_result1.value() << std::endl;
    } else {
        std::cout << "Fehler: " << proc_result1.error().to_string() << std::endl;
    }
    
    std::vector<int> numbers2 = {100, 200, 300, 400};
    auto proc_result2 = process_calculation(numbers2);
    if (proc_result2) {
        std::cout << "Ergebnis: " << proc_result2.value() << std::endl;
    } else {
        std::cout << "Fehler: " << proc_result2.error().to_string() << std::endl;
    }
    
    std::vector<int> numbers3 = {};
    auto proc_result3 = process_calculation(numbers3);
    if (proc_result3) {
        std::cout << "Ergebnis: " << proc_result3.value() << std::endl;
    } else {
        std::cout << "Fehler: " << proc_result3.error().to_string() << std::endl;
    }
    
    // Beispiel 4: Error-Reporting und -Statistik
    std::cout << "\nBeispiel 4: Error-Reporting und -Statistik" << std::endl;
    demonstrate_error_reporting();
}

} // namespace quicsand

// Optional: Hauptfunktion zum direkten Ausführen des Beispiels
int main() {
    quicsand::run_error_handling_demo();
    return 0;
}
