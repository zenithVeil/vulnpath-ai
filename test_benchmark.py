# test_benchmark.py - Test VulnPath-AI on sample files
import os
import sys
import json
import time
from pathlib import Path

from analyze_hybrid import VulnPathAI

# Findings at or above this confidence count as detections.
# Below it, a finding is treated as low-confidence noise (allowed on safe files).
CONFIDENCE_THRESHOLD = 0.7

SAMPLE_ROOT = Path("samples")
VULNERABLE_DIR = SAMPLE_ROOT / "vulnerable"
SAFE_DIR = SAMPLE_ROOT / "safe"

SOURCE_EXTENSIONS = set(VulnPathAI.LANGUAGE_EXTENSIONS.keys())


class BenchmarkTester:
    def __init__(self):
        self.analyzer = VulnPathAI()
        self.file_results = []
        self.results = {
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0,
            "total_time": 0,
            "test_count": 0,
            "confidence_threshold": CONFIDENCE_THRESHOLD,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "accuracy": 0.0,
        }

    def discover_cases(self):
        """Load every source file under samples/vulnerable and samples/safe."""
        cases = []
        for expected, directory in (("vulnerable", VULNERABLE_DIR), ("safe", SAFE_DIR)):
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS:
                    cases.append({
                        "file": str(path).replace("\\", "/"),
                        "expected": expected,
                        "description": "%s sample (%s)" % (expected, path.name),
                    })
        return cases

    def significant_findings(self, vulns):
        return [v for v in vulns if float(v.get("confidence", 0) or 0) >= CONFIDENCE_THRESHOLD]

    def run_tests(self):
        """Run tests on all sample files"""
        print("=" * 60)
        print("VulnPath-AI Benchmark Test")
        print("=" * 60)
        print()

        test_cases = self.discover_cases()

        if not test_cases:
            print("No sample files found under samples/vulnerable/ or samples/safe/.")
            return

        print("Test Cases:")
        print("   Vulnerable dir: %s (%d files)" % (
            VULNERABLE_DIR.as_posix(),
            sum(1 for t in test_cases if t["expected"] == "vulnerable"),
        ))
        print("   Safe dir:       %s (%d files)" % (
            SAFE_DIR.as_posix(),
            sum(1 for t in test_cases if t["expected"] == "safe"),
        ))
        print("   Confidence threshold: %s (safe files may have only lower-confidence findings)" % CONFIDENCE_THRESHOLD)
        print()

        print("Running Tests...")
        print("-" * 60)

        for test in test_cases:
            file_path = test["file"]
            if not os.path.exists(file_path):
                print("Skipping %s (file not found)" % file_path)
                continue

            start_time = time.time()
            result = self.analyzer.analyze_with_ast(file_path)
            elapsed_time = time.time() - start_time

            self.results["test_count"] += 1
            self.results["total_time"] += elapsed_time

            vulns = result.get("vulnerabilities", []) if "error" not in result else []
            significant = self.significant_findings(vulns)
            detected = len(significant) > 0
            expected_vulnerable = test["expected"] == "vulnerable"

            if expected_vulnerable and detected:
                self.results["true_positives"] += 1
                outcome = "true_positive"
                status = "PASS"
            elif (not expected_vulnerable) and (not detected):
                self.results["true_negatives"] += 1
                outcome = "true_negative"
                status = "PASS"
            elif (not expected_vulnerable) and detected:
                self.results["false_positives"] += 1
                outcome = "false_positive"
                status = "FAIL"
            else:
                self.results["false_negatives"] += 1
                outcome = "false_negative"
                status = "FAIL"

            vuln_names = [v.get("vulnerability_type", "Unknown") for v in significant]
            low_names = [
                v.get("vulnerability_type", "Unknown")
                for v in vulns
                if float(v.get("confidence", 0) or 0) < CONFIDENCE_THRESHOLD
            ]

            record = {
                "file": file_path,
                "expected": test["expected"],
                "outcome": outcome,
                "passed": status == "PASS",
                "significant_findings": len(significant),
                "low_confidence_findings": len(low_names),
                "vulnerabilities": vuln_names,
                "low_confidence": low_names,
                "time_seconds": elapsed_time,
            }
            self.file_results.append(record)

            print("%s | %s" % (status, os.path.basename(file_path)))
            print("      Expected: %s | Significant findings: %d (low-confidence ignored: %d)" % (
                test["expected"],
                len(significant),
                len(low_names),
            ))
            print("      Vulnerabilities: %s" % (", ".join(vuln_names[:5]) if vuln_names else "None"))
            if low_names:
                print("      Low-confidence: %s" % ", ".join(low_names[:5]))
            print("      Time: %.2fs" % elapsed_time)
            print()

        self.print_summary()

    def compute_metrics(self):
        tp = self.results["true_positives"]
        fp = self.results["false_positives"]
        tn = self.results["true_negatives"]
        fn = self.results["false_negatives"]
        total = self.results["test_count"]

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0

        self.results["precision"] = precision
        self.results["recall"] = recall
        self.results["f1"] = f1
        self.results["accuracy"] = accuracy
        return precision, recall, f1, accuracy

    def print_summary(self):
        """Print test summary with metrics"""
        print("-" * 60)
        print("Test Summary")
        print("=" * 60)

        tp = self.results["true_positives"]
        fp = self.results["false_positives"]
        tn = self.results["true_negatives"]
        fn = self.results["false_negatives"]
        total = self.results["test_count"]

        if total == 0:
            print("No tests were run.")
            return

        precision, recall, f1, accuracy = self.compute_metrics()

        print("\nTest Results:")
        print("   Total Tests:       %d" % total)
        print("   True Positives:    %d (vulnerabilities found in vulnerable files)" % tp)
        print("   True Negatives:    %d (no significant findings in safe files)" % tn)
        print("   False Positives:   %d (significant findings in safe files)" % fp)
        print("   False Negatives:   %d (missed vulnerabilities)" % fn)

        print("\nPerformance Metrics:")
        print("   Precision:      %.1f%%" % (precision * 100))
        print("   Recall:         %.1f%%" % (recall * 100))
        print("   F1 Score:       %.1f%%" % (f1 * 100))
        print("   Accuracy:       %.1f%%" % (accuracy * 100))
        print("   Total Time:     %.2fs" % self.results["total_time"])
        print("   Avg Time:       %.2fs per file" % (self.results["total_time"] / total))

        print("\nGrade: %s" % self.calculate_grade())
        self.save_report()

    def save_report(self):
        """Save test results to file"""
        self.compute_metrics()
        report = {
            "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": self.results,
            "files": self.file_results,
            "grade": self.calculate_grade(),
        }

        with open("test_results.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        print("\nDetailed results saved to: test_results.json")

    def calculate_grade(self):
        """Calculate grade based on metrics"""
        total = self.results["test_count"]
        if total == 0:
            return "No tests run"

        accuracy = (self.results["true_positives"] + self.results["true_negatives"]) / total
        if accuracy >= 0.90:
            return "Excellent"
        if accuracy >= 0.70:
            return "Good"
        if accuracy >= 0.50:
            return "Fair"
        return "Needs Improvement"


def main():
    tester = BenchmarkTester()
    tester.run_tests()

    print("\n" + "=" * 60)
    print("Benchmark Complete!")
    print("=" * 60)

    if tester.results["false_positives"] or tester.results["false_negatives"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
