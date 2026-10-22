{%- import "macros.ts" as ts -%}

// ==========
// Record definitions:
// ==========
{%- for record_def in ci.record_definitions() | sort_entries | filter_hidden %}
{% call ts::docstring(record_def, 0) %}{% endcall %}
export interface {{ record_def.name() | typescript_class_name }} {
  {%- for field_def in record_def.fields() -%}
  {% call ts::struct_field(field_def, 2) %}{% endcall %}
  {%- endfor %}
}
{%- endfor %}

// ==========
// Enum definitions:
// ==========
{%- for enum_def in ci.enum_definitions() | sort_entries | filter_hidden %}
{%- include "Enum.ts" %}
{%- endfor %}

// ==========
// Object definitions:
// ==========
{%- for object_def in ci.object_definitions() | sort_entries | filter_hidden %}
{% call ts::docstring(object_def, 0) %}{% endcall %}
export interface {{ object_def.name() | typescript_class_name }} {
  {%- for method_def in object_def.methods().as_slice() | sort_entries -%}
  {% call ts::docstring(method_def, 2) %}{% endcall %}
  {{ method_def.name() | typescript_fn_name }}(
    {%- call ts::param_list(method_def) -%}{%- endcall -%}
    ): {% call ts::function_return_type(method_def) %}{% endcall %};
  {%- endfor %}
}
{%- endfor %}

