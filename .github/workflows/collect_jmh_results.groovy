import groovy.json.JsonSlurper
import net.steppschuh.markdowngenerator.table.Table

import java.nio.file.Files
import java.nio.file.Path
import java.math.RoundingMode

@GrabResolver(name='jitpack.io', root='https://jitpack.io/')
@GrabResolver(name = 'central', root='https://repo1.maven.org/maven2/')
@Grapes([
    @Grab('org.apache.groovy:groovy-json:4.0.13'),
    @Grab('com.github.Steppschuh:Java-Markdown-Generator:1.3.2')
])

final results = [:] as TreeMap

final resultsPath = Path.of('build/jmh_results')
final files = Files.list(resultsPath).map { it.resolve('jmh_results.json') }
for (def file : files) {
    if (!file.parent.fileName.toString().startsWith('jmh-') || !Files.exists(file))
        continue
    def json = new JsonSlurper().parse(file.toFile())
    def name = file.parent.fileName.toString().substring('jmh-'.length())
    for (def bench : json) {
        def result = bench.primaryMetric.score.setScale(3, RoundingMode.CEILING)
        if (!bench.primaryMetric.scoreError.equals('NaN'))
            result += ' ± ' + bench.primaryMetric.scoreError.setScale(3, RoundingMode.CEILING)
        result += bench.primaryMetric.scoreUnit
        results.computeIfAbsent(bench.benchmark, { [:] as TreeMap }).put(name, result)
    }
}
def output = ""
results.forEach { bench, values -> 
    final table = new Table.Builder()
        .withAlignments(Table.ALIGN_RIGHT, Table.ALIGN_RIGHT)
        .addRow('JDK name & Version', 'Benchmark results')
    values.forEach { jvm, result -> table.addRow(jvm, result) }
    
    output += '### `' + bench + '` results\n' +
              table.build() + '\n' +
              '\n'
}

new File('jmh_results.md').text = output