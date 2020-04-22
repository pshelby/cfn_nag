# frozen_string_literal: true

require 'cfn-nag/violation'
require 'cfn-nag/util/truthy'
require_relative 'base'

class DLMLifecyclePolicyEncryptedRule < BaseRule
  def rule_text
    'AWS DLM LifecyclePolicy should use encryption when copying rules.'
  end

  def rule_type
    Violation::WARNING
  end

  def rule_id
    'W70'
  end

  def audit_impl(cfn_model)
    violating_policies = cfn_model.resources_by_type('AWS::DLM::LifecyclePolicy').select do |policy|
      violating_schedules = policy.policyDetails.fetch('Schedules', []).select do |sched|
        violating_rules = sched.fetch('CrossRegionCopyRules', []).select do |rule|
          not_truthy?(rule['Encrypted'])
        end

        !violating_rules.empty?
      end

      !violating_schedules.empty?
    end

    violating_policies.map(&:logical_resource_id)
  end
end
