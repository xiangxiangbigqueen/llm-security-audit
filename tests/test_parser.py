"""仓库解析模块测试"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.repo_parser import RepoParser
from parser.language_detector import LanguageDetector


def test_language_detector():
    """测试语言检测"""
    detector = LanguageDetector()
    sample_dir = os.path.join(os.path.dirname(__file__), "sample_vulnerable_code")

    if os.path.exists(sample_dir):
        result = detector.detect(sample_dir)
        print(f"语言检测结果: {result}")
        assert "C" in result or "PHP" in result, "应检测到C或PHP语言"

        # 测试获取目标文件
        files = detector.get_target_files(sample_dir)
        print(f"目标文件数: {len(files)}")
        assert len(files) > 0, "应找到目标文件"

        for f in files:
            print(f"  - {os.path.relpath(f, sample_dir)}")

    print("✓ 语言检测测试通过")


def test_repo_parser():
    """测试仓库解析"""
    parser = RepoParser()
    sample_dir = os.path.join(os.path.dirname(__file__), "sample_vulnerable_code")

    if os.path.exists(sample_dir):
        # 测试本地目录解析
        path = parser.parse_local(sample_dir)
        assert os.path.isdir(path)

        # 测试元信息获取
        metadata = parser.get_metadata(sample_dir)
        print(f"\n项目元信息:")
        print(f"  名称: {metadata.name}")
        print(f"  语言: {metadata.languages}")
        print(f"  文件数: {metadata.file_count}")
        print(f"  总行数: {metadata.total_lines}")
        print(f"  主语言: {metadata.primary_language}")

        assert metadata.file_count > 0
        assert metadata.total_lines > 0

    print("✓ 仓库解析测试通过")


if __name__ == "__main__":
    test_language_detector()
    test_repo_parser()
    print("\n所有测试通过!")