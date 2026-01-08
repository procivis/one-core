{% macro param_list(func) %}
    {%- for arg in func.arguments() -%}
        {{ arg.name() | typescript_var_name }}: {{ arg | typescript_type_name }}
        {%- if !loop.last %}, {% endif -%}
    {%- endfor -%}
{%- endmacro %}

{%- macro docstring(defn, indent_level) %}
{%- if let Some(s) = defn.docstring() %}
{{ s | typescript_docstring(indent_level) }}
{%- endif %}
{%- endmacro %}

{%- macro function_return_type(func_def) -%}
    {%- if func_def.is_async() -%}Promise<{%- endif -%}
    {%- if let Some(ret_type) = func_def.return_type() -%}
        {{ ret_type | typescript_type_name }}
    {%- else -%}
        void
    {%- endif %}
    {%- if func_def.is_async() -%}>{%- endif -%}
{%- endmacro -%}

{%- macro struct_field(field_def, indent_level) %}
{%- call docstring(field_def, indent_level) %}
{% call indent(indent_level) -%}
{%- if let Type::Optional{ inner_type } = field_def.as_type() -%}
    {{field_def.name() | typescript_var_name}}?: {{inner_type | typescript_type_name}};
{%- else -%}
    {{field_def.name() | typescript_var_name}}: {{field_def | typescript_type_name}};
{%- endif -%}
{%- endmacro -%}

{%- macro indent(indent_level) -%}
    {%- for _ in 0..indent_level %} {% endfor -%}
{%- endmacro -%}