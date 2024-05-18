use crate::error::Result;
use crate::footer::write_footer;
use crate::formatter::FormatterOptions;
use crate::writers::Output;
use crate::Results;
use crate::Results::Query;
use colored::Colorize;
use num_format::Locale;
use prettytable::format::{Alignment, TableFormat};
use prettytable::{Cell, Table};
use rsql_drivers::{QueryResult, Value};
use std::str::FromStr;

/// Format the results of a query into a table and write to the output.
pub async fn format(
    table_format: TableFormat,
    options: &FormatterOptions,
    results: &mut Results,
    output: &mut Output,
) -> Result<()> {
    let mut rows: u64 = 0;

    if let Query(query_result) = results {
        if query_result.columns().await.is_empty() {
            write_footer(options, results, 0, output).await?;
            return Ok(());
        }

        let mut table = Table::new();
        table.set_format(table_format);

        if options.header {
            process_headers(query_result, &mut table).await;
        }

        rows = process_data(options, query_result, &mut table).await?;

        table.print(output)?;
    }

    write_footer(options, results, rows, output).await?;
    Ok(())
}

async fn process_headers(query_result: &mut Box<dyn QueryResult>, table: &mut Table) {
    let mut row_data = prettytable::Row::default();

    for column in &query_result.columns().await {
        let cell = Cell::new_align(&column.to_string(), Alignment::CENTER);
        row_data.add_cell(cell);
    }

    table.set_titles(row_data);
}

async fn process_data(
    options: &FormatterOptions,
    query_result: &mut Box<dyn QueryResult>,
    table: &mut Table,
) -> Result<u64> {
    let locale = Locale::from_str(options.locale.as_str()).unwrap_or(Locale::en);
    let mut rows: u64 = 0;
    while let Some(row) = query_result.next().await {
        let mut row_data = prettytable::Row::default();

        for data in row.into_iter() {
            let mut alignment = Alignment::LEFT;
            let mut data = match data {
                Value::Null => "NULL".to_string(),
                _ => {
                    if data.is_numeric() {
                        alignment = Alignment::RIGHT;
                    }
                    data.to_formatted_string(&locale)
                }
            };

            if options.color && rows % 2 == 0 {
                data = data.dimmed().to_string();
            }

            let cell = Cell::new_align(&data, alignment);
            row_data.add_cell(cell);
        }

        rows += 1;
        table.add_row(row_data);
    }

    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writers::Output;
    use crate::Results::Execute;
    use indoc::indoc;
    use prettytable::format::consts::FORMAT_DEFAULT;
    use rsql_drivers::{MemoryQueryResult, Row, Value};
    use std::time::Duration;

    const COLUMN_HEADER: &str = "id";

    fn query_result_no_columns() -> Results {
        let query_result = MemoryQueryResult::new(vec![], vec![]);
        Query(Box::new(query_result))
    }

    fn query_result_no_rows() -> Results {
        let query_result = MemoryQueryResult::new(vec![COLUMN_HEADER.to_string()], vec![]);
        Query(Box::new(query_result))
    }

    fn query_result_one_row() -> Results {
        let query_result = MemoryQueryResult::new(
            vec![COLUMN_HEADER.to_string()],
            vec![Row::new(vec![Value::I64(12345)])],
        );
        Query(Box::new(query_result))
    }

    fn query_result_two_rows() -> Results {
        let query_result = MemoryQueryResult::new(
            vec![COLUMN_HEADER.to_string()],
            vec![
                Row::new(vec![Value::Null]),
                Row::new(vec![Value::I64(12345)]),
            ],
        );
        Query(Box::new(query_result))
    }

    fn query_result_number_and_string() -> Results {
        let query_result = MemoryQueryResult::new(
            vec![
                "number".to_string(),
                "string".to_string(),
                "text".to_string(),
            ],
            vec![Row::new(vec![
                Value::I64(42),
                Value::String("foo".to_string()),
                Value::String("Lorem ipsum dolor sit amet".to_string()),
            ])],
        );
        Query(Box::new(query_result))
    }

    async fn test_format(
        options: &mut FormatterOptions,
        results: &mut Results,
    ) -> anyhow::Result<String> {
        let output = &mut Output::default();
        options.elapsed = Duration::from_nanos(9);

        format(*FORMAT_DEFAULT, options, results, output).await?;

        Ok(output.to_string().replace("\r\n", "\n"))
    }

    #[tokio::test]
    async fn test_execute_format() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: false,
            locale: "en".to_string(),
            ..Default::default()
        };
        let mut results = Execute(42);

        let output = test_format(&mut options, &mut results).await?;
        let expected = "42 rows (9ns)\n";
        assert_eq!(output, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_query_format_no_rows() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: false,
            locale: "en".to_string(),
            ..Default::default()
        };
        let mut results = query_result_no_rows();

        let output = test_format(&mut options, &mut results).await?;
        let expected = indoc! {r#"
            +----+
            | id |
            +====+
            +----+
            0 rows (9ns)
        "#};
        assert_eq!(output, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_query_format_footer_no_timer() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: false,
            footer: true,
            locale: "en".to_string(),
            timer: false,
            ..Default::default()
        };
        let mut results = query_result_no_rows();

        let output = test_format(&mut options, &mut results).await?;
        let expected = indoc! {r#"
            +----+
            | id |
            +====+
            +----+
            0 rows
        "#};
        assert_eq!(output, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_query_format_two_rows_without_color() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: false,
            locale: "en".to_string(),
            ..Default::default()
        };
        let mut results = query_result_two_rows();

        let output = test_format(&mut options, &mut results).await?;
        let expected = indoc! {r#"
            +--------+
            |   id   |
            +========+
            | NULL   |
            +--------+
            | 12,345 |
            +--------+
            2 rows (9ns)
        "#};
        assert_eq!(output, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_query_format_two_rows_with_color() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: true,
            locale: "en".to_string(),
            ..Default::default()
        };
        let mut results = query_result_two_rows();

        let output = test_format(&mut options, &mut results).await?;
        assert!(output.contains("id"));
        assert!(output.contains("NULL"));
        assert!(output.contains("12,345"));
        assert!(output.contains("2 rows"));
        assert!(output.contains("(9ns)"));
        Ok(())
    }

    #[tokio::test]
    async fn test_query_format_no_header_and_no_footer() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: false,
            footer: false,
            header: false,
            locale: "en".to_string(),
            ..Default::default()
        };
        let mut results = query_result_one_row();

        let output = test_format(&mut options, &mut results).await?;
        let expected = indoc! {r#"
            +--------+
            | 12,345 |
            +--------+
        "#};
        assert_eq!(output, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_query_format_no_columns() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: false,
            locale: "en".to_string(),
            ..Default::default()
        };
        let mut results = query_result_no_columns();

        let output = test_format(&mut options, &mut results).await?;
        let expected = indoc! {r#"
            0 rows (9ns)
        "#};
        assert_eq!(output, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_query_align_numbers_and_strings() -> anyhow::Result<()> {
        let mut options = FormatterOptions {
            color: false,
            locale: "en".to_string(),
            ..Default::default()
        };
        let mut results = query_result_number_and_string();

        let output = test_format(&mut options, &mut results).await?;
        let expected = indoc! {r#"
            +--------+--------+----------------------------+
            | number | string |            text            |
            +========+========+============================+
            |     42 | foo    | Lorem ipsum dolor sit amet |
            +--------+--------+----------------------------+
            1 row (9ns)
        "#};
        assert_eq!(output, expected);
        Ok(())
    }
}
