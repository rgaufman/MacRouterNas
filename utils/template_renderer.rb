#!/usr/bin/env ruby
# frozen_string_literal: true

# Template renderer for MacRouter utilities
# Provides functionality for loading and rendering ERB templates

require 'erb'
require 'semantic_logger'

module MacRouterUtils
  class TemplateRenderer
    include SemanticLogger::Loggable

    def initialize(template_dir = nil)
      @template_dir = template_dir || File.join(File.dirname(__FILE__, 2), 'templates')
      @logger = SemanticLogger['TemplateRenderer']
    end

    # Render a template with the given variables
    # @param template_name [String] The name of the template file (without .erb extension)
    # @param variables [Hash] The variables to use in the template
    # @return [String] The rendered template
    def render(template_name, variables = {})
      template_path = File.join(@template_dir, "#{template_name}.erb")

      unless File.exist?(template_path)
        @logger.error("Template not found: #{template_path}")
        raise "Template not found: #{template_path}"
      end

      template_content = File.read(template_path)
      erb = ERB.new(template_content, trim_mode: '-')

      # Create a binding with the variables
      context = TemplateContext.new(variables)

      erb.result(context.get_binding)
    end

    # Helper class to create a binding with variables
    class TemplateContext
      def initialize(variables)
        variables.each do |key, value|
          instance_variable_set("@#{key}", value)
        end
      end

      def get_binding
        binding
      end
    end
  end
end
