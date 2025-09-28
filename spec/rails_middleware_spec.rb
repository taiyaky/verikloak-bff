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

    it 'detects the core middleware when it is referenced by string name' do
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield('Verikloak::Middleware')
      expect(stack).to receive(:insert_after).with(Verikloak::Middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_after_core(stack, logger: nil)).to be(true)
    end

    it 'detects the core middleware when wrapped in an array entry' do
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield([Verikloak::Middleware, {}])
      expect(stack).to receive(:insert_after).with(Verikloak::Middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_after_core(stack, logger: nil)).to be(true)
    end

    it 'detects the core middleware when wrapped in a middleware entry with args' do
      middleware_entry = double('MiddlewareEntry', klass: Verikloak::Middleware, args: [])
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield(middleware_entry)
      expect(stack).to receive(:insert_after).with(Verikloak::Middleware, Verikloak::BFF::HeaderGuard)

      expect(described_class.insert_after_core(stack, logger: nil)).to be(true)
    end

    it 'detects the core middleware by name when stack contains complex objects' do
      complex_object = double('ComplexObject', name: 'Verikloak::Middleware')
      allow(stack).to receive(:include?).and_return(false)
      allow(stack).to receive(:each).and_yield(complex_object)
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

    it 'gracefully handles when verikloak gem is not loaded' do
      hide_const('Verikloak')

      expect(stack).not_to receive(:insert_after)
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('Skipping Verikloak::BFF::HeaderGuard insertion'))

      expect(described_class.insert_after_core(stack, logger: logger)).to be(false)
    end

    it 'handles when Verikloak::Middleware constant is not defined' do
      hide_const('Verikloak::Middleware')

      expect(stack).not_to receive(:insert_after)
      logger = instance_double('Logger')
      expect(logger).to receive(:warn).with(a_string_matching('Skipping Verikloak::BFF::HeaderGuard insertion'))

      expect(described_class.insert_after_core(stack, logger: logger)).to be(false)
    end
  end
end
