# test_benchmark.py - Test VulnPath-AI on sample files
import os
import sys
import json
import time
from pathlib import Path

# Import the analyzer
from analyze_hybrid import VulnPathAI

class BenchmarkTester:
    def __init__(self):
        self.analyzer = VulnPathAI()
        self.results = {
            "true_positives": 0,
            "false_positives": 0,
            "true_negatives": 0,
            "false_negatives": 0,
            "total_time": 0,
            "test_count": 0
        }
    
    def run_tests(self):
        """Run tests on all sample files"""
        print("=" * 60)
        print("🧪 VulnPath-AI Benchmark Test")
        print("=" * 60)
        print()
        
        # Define test cases
        test_cases = [
            # Vulnerable files (should detect)
            {
                "file": "samples/sqli_example.py",
                "expected": "vulnerable",
                "description": "SQL Injection Example"
            },
            {
                "file": "samples/command_injection_example.py",
                "expected": "vulnerable",
                "description": "Command Injection Example"
            },
            {
                "file": "samples/hardcoded_secrets.js",
                "expected": "vulnerable",
                "description": "Hardcoded Secrets Example"
            },
            {
                "file": "samples/xss_example.js",
                "expected": "vulnerable",
                "description": "XSS Example"
            },
        ]
        
        # Check if sample files exist
        sample_files_exist = False
        for test in test_cases:
            if os.path.exists(test["file"]):
                sample_files_exist = True
                break
        
        if not sample_files_exist:
            print("⚠️ No sample files found. Please ensure samples/ directory exists.")
            print("   Run: python analyze_hybrid.py samples/sqli_example.py")
            return
        
        print("📋 Test Cases:")
        for test in test_cases:
            print(f"   - {test['description']}: {test['file']}")
        print()
        
        print("🔄 Running Tests...")
        print("-" * 60)
        
        for test in test_cases:
            file_path = test["file"]
            
            if not os.path.exists(file_path):
                print(f"⚠️ Skipping {file_path} (file not found)")
                continue
            
            # Analyze the file
            start_time = time.time()
            result = self.analyzer.analyze_file(file_path)
            elapsed_time = time.time() - start_time
            
            self.results["test_count"] += 1
            self.results["total_time"] += elapsed_time
            
            # Check results
            vulns = result.get("vulnerabilities", [])
            found = len(vulns) > 0
            
            # Determine if test passed
            expected_vulnerable = test["expected"] == "vulnerable"
            passed = found == expected_vulnerable
            
            # Update metrics
            if passed and found:
                self.results["true_positives"] += 1
                status = "✅ PASS"
            elif passed and not found:
                self.results["true_negatives"] += 1
                status = "✅ PASS"
            elif not passed and found:
                self.results["false_positives"] += 1
                status = "❌ FAIL"
            else:
                self.results["false_negatives"] += 1
                status = "❌ FAIL"
            
            # Print result
            vuln_count = len(vulns)
            vuln_names = [v.get('vulnerability_type', 'Unknown') for v in vulns]
            vuln_list = ", ".join(vuln_names[:3]) if vuln_names else "None"
            
            print(f"{status} | {os.path.basename(file_path)}")
            print(f"      Expected: {test['expected']} | Found: {vuln_count} vulnerabilities")
            print(f"      Vulnerabilities: {vuln_list}")
            print(f"      Time: {elapsed_time:.2f}s")
            print()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary with metrics"""
        print("-" * 60)
        print("📊 Test Summary")
        print("=" * 60)
        
        tp = self.results["true_positives"]
        fp = self.results["false_positives"]
        tn = self.results["true_negatives"]
        fn = self.results["false_negatives"]
        total = self.results["test_count"]
        
        if total == 0:
            print("⚠️ No tests were run.")
            return
        
        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / total if total > 0 else 0
        
        print(f"\n📋 Test Results:")
        print(f"   Total Tests:       {total}")
        print(f"   True Positives:    {tp} (Correctly found vulnerabilities)")
        print(f"   True Negatives:    {tn} (Correctly found no vulnerabilities)")
        print(f"   False Positives:   {fp} (False alarms)")
        print(f"   False Negatives:   {fn} (Missed vulnerabilities)")
        
        print(f"\n📊 Performance Metrics:")
        print(f"   ✅ Precision:      {precision*100:.1f}%")
        print(f"   ✅ Recall:         {recall*100:.1f}%")
        print(f"   ✅ F1 Score:       {f1*100:.1f}%")
        print(f"   ✅ Accuracy:       {accuracy*100:.1f}%")
        print(f"   ⏱️  Total Time:    {self.results['total_time']:.2f}s")
        print(f"   ⏱️  Avg Time:      {(self.results['total_time']/total):.2f}s per file")
        
        # Grade
        if accuracy >= 0.90:
            grade = "🌟 Excellent! Your tool is working great!"
        elif accuracy >= 0.70:
            grade = "👍 Good! Your tool is working well."
        elif accuracy >= 0.50:
            grade = "📈 Fair. Your tool needs some improvement."
        else:
            grade = "⚠️ Poor. Your tool may need significant improvements."
        
        print(f"\n🎯 Grade: {grade}")
        
        # Save report
        self.save_report()
    
    def save_report(self):
        """Save test results to file"""
        report = {
            "test_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "results": self.results,
            "grade": self.calculate_grade()
        }
        
        # Fixed: Use utf-8 encoding
        with open("test_results.json", "w", encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed results saved to: test_results.json")
    
    def calculate_grade(self):
        """Calculate grade based on metrics"""
        tp = self.results["true_positives"]
        fp = self.results["false_positives"]
        tn = self.results["true_negatives"]
        fn = self.results["false_negatives"]
        total = self.results["test_count"]
        
        if total == 0:
            return "No tests run"
        
        accuracy = (tp + tn) / total if total > 0 else 0
        
        if accuracy >= 0.90:
            return "🌟 Excellent"
        elif accuracy >= 0.70:
            return "👍 Good"
        elif accuracy >= 0.50:
            return "📈 Fair"
        else:
            return "⚠️ Needs Improvement"

def main():
    tester = BenchmarkTester()
    tester.run_tests()
    
    print("\n" + "=" * 60)
    print("🏆 Benchmark Complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()