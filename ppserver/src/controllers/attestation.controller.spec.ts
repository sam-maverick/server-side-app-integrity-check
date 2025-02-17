import { Test, TestingModule } from '@nestjs/testing';
import { AttestationController } from './attestation.controller';
import { AppService } from '../app.service';



describe('AttestationController', () => {
    let controller: AttestationController;

    beforeEach(async () => {

        const module: TestingModule = await Test.createTestingModule({
            controllers: [AttestationController],
        }).compile();

        controller = module.get<AttestationController>(AttestationController);

    });

    it('should be defined', () => {
        expect(controller).toBeDefined();
    });
});
