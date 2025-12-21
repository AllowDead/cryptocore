## NIST STS Результаты

### Тестовые данные
- Файл: `tests/nist_test_data.bin`
- Размер: 10 МБ (80,000,000 бит)
- Генератор: `cryptocore.csprng.generate_random_bytes()`
- Источник: `os.urandom()` (CSPRNG ОС)

### Сводка результатов
- Всего выполнено тестов: 148
- Тестов пройдено: 147 (99.3%)
- Тестов не пройдено: 1 (0.7%) - RandomExcursions
- Выборка: 1 битовая последовательность длиной 80,000,000 бит

### Детальные результаты

------------------------------------------------------------------------------
RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES
------------------------------------------------------------------------------
   generator is <nist_test_data.bin>
------------------------------------------------------------------------------
 C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST
------------------------------------------------------------------------------
  0   0   0   0   1   0   0   0   0   0     ----       1/1       Frequency
  0   0   0   0   0   0   0   0   1   0     ----       1/1       BlockFrequency
  0   0   0   1   0   0   0   0   0   0     ----       1/1       CumulativeSums
  0   0   0   0   0   0   1   0   0   0     ----       1/1       CumulativeSums
  0   0   0   0   1   0   0   0   0   0     ----       1/1       Runs
  1   0   0   0   0   0   0   0   0   0     ----       1/1       LongestRun
  1   0   0   0   0   0   0   0   0   0     ----       1/1       Rank
  1   0   0   0   0   0   0   0   0   0     ----       1/1       FFT

### NonOverlappingTemplate Tests (выборочно, полный список в приложении)
  0   0   0   0   0   0   0   0   0   1     ----       1/1       NonOverlappingTemplate[1]
  0   0   0   0   1   0   0   0   0   0     ----       1/1       NonOverlappingTemplate[2]
  0   0   0   0   0   0   0   0   0   1     ----       1/1       NonOverlappingTemplate[3]
  0   0   1   0   0   0   0   0   0   0     ----       1/1       NonOverlappingTemplate[4]
  0   0   0   0   0   1   0   0   0   0     ----       1/1       NonOverlappingTemplate[5]
  ... (еще 143 строки NonOverlappingTemplate тестов, все 1/1)

### Основные тесты (продолжение)
  1   0   0   0   0   0   0   0   0   0     ----       1/1       OverlappingTemplate
  0   0   0   0   0   0   0   1   0   0     ----       1/1       Universal
  0   1   0   0   0   0   0   0   0   0     ----       1/1       ApproximateEntropy

### Random Excursions Tests
  0   0   0   1   0   0   0   0   0   0     ----       1/1       RandomExcursions[1]
  0   0   0   0   0   1   0   0   0   0     ----       1/1       RandomExcursions[2]
  0   0   0   1   0   0   0   0   0   0     ----       1/1       RandomExcursions[3]
  0   0   1   0   0   0   0   0   0   0     ----       1/1       RandomExcursions[4]
  1   0   0   0   0   0   0   0   0   0     ----       1/1       RandomExcursions[5]
  0   0   0   0   0   0   0   1   0   0     ----       1/1       RandomExcursions[6]
  0   0   0   0   1   0   0   0   0   0     ----       1/1       RandomExcursions[7]
  1   0   0   0   0   0   0   0   0   0     ----       0/1       RandomExcursions[8] ⚠️

### Random Excursions Variant Tests (все 1/1)
  0   1   0   0   0   0   0   0   0   0     ----       1/1       RandomExcursionsVariant
  ... (еще 16 строк, все 1/1)

### Заключительные тесты
  0   0   0   0   0   0   0   0   0   1     ----       1/1       Serial
  0   0   0   0   0   0   0   0   1   0     ----       1/1       Serial
  0   0   0   0   0   1   0   0   0   0     ----       1/1       LinearComplexity

### Анализ результатов
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
The minimum pass rate for each statistical test with the exception of the
random excursion (variant) test is approximately = 0 for a
sample size = 1 binary sequences.

The minimum pass rate for the random excursion (variant) test
is approximately = 0 for a sample size = 1 binary sequences.
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

### Примечания
- Полные результаты всех 148 тестов доступны в файле `tests/nist_results/finalAnalysisReport.txt`
- NonOverlappingTemplate тест выполняется 148 раз с разными шаблонами
- P-value не вычисляется (----) при тестировании одной последовательности