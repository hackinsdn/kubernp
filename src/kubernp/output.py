"""Output module."""
import pandas as pd
from tabulate import tabulate
from IPython.core.display_functions import display

def show_table(
    data,
    output=None,
    quiet=False,
    headers=False,
    fields=None,
    title="",
    pretty_names_dict={},
    empty_msg="No content",
):
    """
    Based on FABRIC fabrictestbed-extensions package.

    Form a table that we can display.
    """

    table, table_headers = create_show_table(
        data, fields=fields, pretty_names_dict=pretty_names_dict
    )

    if output == "text" or output == "default":
        return show_table_text(table, quiet=quiet, headers=table_headers, empty_msg=empty_msg)
    elif output == "json":
        return show_table_json(data, quiet=quiet)
    elif output == "dict":
        return show_table_dict(data, quiet=quiet)
    elif output == "pandas" or output == "jupyter_default":
        return show_table_jupyter(
            table,
            headers=fields,
            title=title,
            quiet=quiet,
            empty_msg=empty_msg,
        )
    else:
        log.error(f"Unknown output type: {output}")

def show_table_text(table, quiet=False, headers=[], empty_msg="No content"):
    """
    Based on FABRIC fabrictestbed-extensions package.

    Make a table in text format.
    """
    printable_table = tabulate(table, headers=headers)
    if not quiet:
        if table:
            print(f"{printable_table}")
        elif empty_msg:
            print(empty_msg)
        return
    return printable_table

def show_table_json(data, quiet=False):
    """
    Based on FABRIC fabrictestbed-extensions package.

    Make a table in JSON format.
    """
    json_str = json.dumps(data, indent=4)

    if not quiet:
        print(f"{json_str}")
        return

    return json_str

def show_table_dict(data, quiet=False):
    """
    Based on FABRIC fabrictestbed-extensions package.

    Show the table.
    """
    if not quiet:
        print(f"{data}")
        return

    return data

def show_table_jupyter(
    table, headers=None, title="", title_font_size="1.25em", quiet=False, empty_msg="No content"
):
    """
    Based on FABRIC fabrictestbed-extensions package.

    Make a table in text form suitable for Jupyter notebooks.

    You normally will not use this method directly; you should
    rather use :py:meth:`show_table()`.

    :param table: A list of lists.
    :param title: The table title.
    :param title_font_size: Font size to use for the table title.
    :param quiet: Setting this to `False` causes the table to be
        displayed.
    :param empty_msg: String message to display when empty.

    :return: a Pandas dataframe.
    :rtype: pd.DataFrame
    """
    printable_table = pd.DataFrame(table)

    properties = {
        "text-align": "left",
        "border": f"1px #202020 solid !important",
    }

    printable_table = printable_table.style.set_caption(title)
    printable_table = printable_table.set_properties(**properties, overwrite=False)
    printable_table = printable_table.hide(axis="index")
    printable_table = printable_table.hide(axis="columns")

    printable_table = printable_table.set_table_styles(
        [
            {
                "selector": "tr:nth-child(even)",
                "props": [
                    ("background", "#dbf3ff"),
                    ("color", "#202020"),
                ],
            }
        ],
        overwrite=False,
    )
    printable_table = printable_table.set_table_styles(
        [
            {
                "selector": "tr:nth-child(odd)",
                "props": [
                    ("background", "#ffffff"),
                    ("color", "#202020"),
                ],
            }
        ],
        overwrite=False,
    )

    caption_props = [
        ("text-align", "center"),
        ("font-size", "150%"),
    ]

    printable_table = printable_table.set_table_styles(
        [{"selector": "caption", "props": caption_props}], overwrite=False
    )

    if not quiet:
        if table:
            display(printable_table)
        elif empty_msg:
            print(empty_msg)
        return

    return printable_table

def create_show_table(data, fields=None, pretty_names_dict={}):
    """
    Based on FABRIC fabrictestbed-extensions package.

    Form a table that we can display.
    """
    table1 = []
    table2 = []
    table_headers = []
    keys = fields if fields else data.keys()
    for field in keys:
        name = pretty_names_dict.get(field, field)
        if isinstance(data[field], list):
            for idx, value in enumerate(data[field]):
                if len(table1) > idx:
                    table1[idx].append(value)
                else:
                    table1.append([value])
            table_headers.append(name)
        table2.append([name, data[field]])

    if len(table_headers) == len(keys):
        return table1, table_headers

    return table2, []

