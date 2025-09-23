# frozen_string_literal: true

RSpec.describe Verikloak::BFF::Rails::Middleware do
  module Verikloak
    class Middleware; end

    class << self
      attr_accessor :config
    end
  end

  describe '.insert_after_core' do
    let(:stack) { double('MiddlewareStack') }

    it 'inserts the header guard when the core middleware is present' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: Verikloak::Middleware))
      expect(stack).to receive(:insert_after).with(Verikloak::Middleware, Verikloak::BFF::HeaderGuard)
      expect(described_class.insert_after_core(stack, logger: nil)).to be(true)
    end

    it 'skips insertion with a warning when the core middleware is missing' do
      allow(stack).to receive(:each)
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('Skipping Verikloak::BFF::HeaderGuard insertion'))
      expect(stack).not_to receive(:insert_after)

      expect(described_class.insert_after_core(stack, logger: logger)).to be(false)
    end

    it 'logs and skips when insertion fails because the core middleware is missing' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: Verikloak::Middleware))
      error = RuntimeError.new('No such middleware to insert after: Verikloak::Middleware')
      allow(stack).to receive(:insert_after).and_raise(error)
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('Skipping Verikloak::BFF::HeaderGuard insertion'))

      expect(described_class.insert_after_core(stack, logger: logger)).to be(false)
    end

    it 're-raises unexpected runtime errors' do
      allow(stack).to receive(:each).and_yield(double('Entry', klass: Verikloak::Middleware))
      allow(stack).to receive(:insert_after).and_raise(RuntimeError, 'boom')

      expect {
        described_class.insert_after_core(stack, logger: nil)
      }.to raise_error(RuntimeError, 'boom')
    end

    it 'respects auto_insert_bff_header_guard configuration' do
      Verikloak.config = double('Config', auto_insert_bff_header_guard: false)
      allow(stack).to receive(:each).and_yield(double('Entry', klass: Verikloak::Middleware))
      expect(stack).not_to receive(:insert_after)

      expect(described_class.insert_after_core(stack, logger: nil)).to be(false)
    ensure
      Verikloak.config = nil
    end
  end
end
